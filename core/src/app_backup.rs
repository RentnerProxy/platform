mod files;

use crate::{app_manager, appliance_process};
use marketplace_artifacts::{digest, invalid, read_file};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    io::{self, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::ExitCode,
};

const APPS: &str = "/var/lib/rentnerproxy/apps";
const MAX_ARCHIVE: usize = 48 * 1024 * 1024;
const MAX_DATA: usize = 32 * 1024 * 1024;
const MAX_NODES: usize = 8192;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Snapshot {
    format_version: u8,
    installations: Value,
    data: BTreeMap<u32, Vec<files::Entry>>,
}

fn app_roots(installations: &Value, pending: Option<&str>) -> io::Result<BTreeMap<u32, PathBuf>> {
    let mut slots = BTreeMap::new();
    for slot in installations
        .as_object()
        .ok_or_else(|| invalid("Invalid backup inventory"))?
        .values()
    {
        let uid = slot["uid"]
            .as_u64()
            .filter(|u| (20000..=59999).contains(u))
            .ok_or_else(|| invalid("Invalid backup UID"))? as u32;
        let removal = slot["removal"].as_str();
        if !matches!(removal, Some("installed" | "removed" | "purged"))
            || slot["databaseProvisioned"] != false
            || !slot["written"].is_null()
        {
            return Err(invalid("Application database recovery is unavailable"));
        }
        if slots
            .insert(
                uid,
                (
                    slot["generation"]
                        .as_u64()
                        .ok_or_else(|| invalid("Missing generation"))?,
                    removal == Some("purged"),
                ),
            )
            .is_some()
        {
            return Err(invalid("Duplicate installation UID"));
        }
    }
    let mut roots = BTreeMap::new();
    let root = Path::new(APPS);
    let entries = match fs::symlink_metadata(root) {
        Ok(m) if m.is_dir() && m.uid() == 0 && m.mode() & 0o7022 == 0 => Some(fs::read_dir(root)?),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        _ => return Err(invalid("Unsafe apps directory")),
    };
    for entry in entries.into_iter().flatten() {
        let entry = entry?;
        let name = entry.file_name();
        let uid = name
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
            .filter(|u| {
                u.to_string().as_str() == name && slots.get(u).is_some_and(|(_, purged)| !purged)
            })
            .ok_or_else(|| invalid("Untracked installation data"))?;
        let root = entry.path();
        let meta = fs::symlink_metadata(&root)?;
        if !meta.is_dir() || meta.uid() != 0 || meta.gid() != uid || meta.mode() & 0o7777 != 0o710 {
            return Err(invalid("Unsafe installation directory"));
        }
        for member in fs::read_dir(&root)? {
            let member = member?;
            if pending.is_some_and(|name| member.file_name() == name) {
                files::check_staging(&member.path())?;
                continue;
            }
            if member.file_name() != "data"
                && member.file_name() != ".provision.lock"
                && member.file_name() != ".manager-owner"
            {
                return Err(invalid("Unsupported installation storage"));
            }
        }
        let (id, slot) = installations
            .as_object()
            .unwrap()
            .iter()
            .find(|(_, s)| s["uid"].as_u64() == Some(u64::from(uid)))
            .ok_or_else(|| invalid("Unknown UID"))?;
        let owner = root.join(".manager-owner");
        let owner_meta = fs::symlink_metadata(&owner)?;
        let app = slot["appId"]
            .as_str()
            .ok_or_else(|| invalid("Missing application identity"))?;
        if !owner_meta.is_file()
            || owner_meta.uid() != 0
            || owner_meta.nlink() != 1
            || owner_meta.mode() & 0o7777 != 0o400
            || read_file(&owner, 256)? != format!("{app}\n{id}\n").as_bytes()
        {
            return Err(invalid("Unverified application storage owner"));
        }
        let data = root.join("data");
        let meta = fs::symlink_metadata(&data)?;
        if !meta.is_dir() || meta.uid() != uid || meta.gid() != uid || meta.mode() & 0o7777 != 0o700
        {
            return Err(invalid("Unsafe installation data directory"));
        }
        roots.insert(uid, data);
    }
    if slots
        .iter()
        .any(|(uid, (generation, purged))| *generation != 0 && !purged && !roots.contains_key(uid))
    {
        return Err(invalid("Provisioned application data is missing"));
    }
    Ok(roots)
}

fn validate_snapshot(snapshot: &Snapshot) -> io::Result<()> {
    let slots = snapshot
        .installations
        .as_object()
        .ok_or_else(|| invalid("Missing app inventory"))?;
    if snapshot.format_version != 1 || slots.is_empty() || slots.len() > 256 {
        return Err(invalid("Invalid app snapshot"));
    }
    let mut uids = BTreeSet::new();
    for slot in slots.values() {
        let uid = slot["uid"]
            .as_u64()
            .filter(|uid| (20000..=59999).contains(uid))
            .ok_or_else(|| invalid("Invalid app snapshot UID"))? as u32;
        let generation = slot["generation"]
            .as_u64()
            .ok_or_else(|| invalid("Missing snapshot generation"))?;
        let removal = slot["removal"].as_str();
        if !uids.insert(uid)
            || !matches!(removal, Some("installed" | "removed" | "purged"))
            || slot["databaseProvisioned"] != false
            || !slot["written"].is_null()
            || (removal == Some("purged") && snapshot.data.contains_key(&uid))
            || (removal != Some("purged") && generation != 0 && !snapshot.data.contains_key(&uid))
        {
            return Err(invalid("Invalid app snapshot storage"));
        }
    }
    let mut budget = files::Budget::default();
    for (uid, entries) in &snapshot.data {
        if !uids.contains(uid) {
            return Err(invalid("Unexpected app snapshot UID"));
        }
        files::validate(entries, &mut budget)?;
    }
    Ok(())
}

fn process(args: &[String]) -> io::Result<()> {
    if let [action, path] = args
        && action == "inspect"
    {
        return validate_snapshot(&serde_json::from_slice(&read_file(
            Path::new(path),
            MAX_ARCHIVE as u64,
        )?)?);
    }
    if unsafe { libc::geteuid() } != 0 {
        return Err(invalid("Application backup requires maintenance ownership"));
    }
    let config = env::var_os("RENTNERPROXY_APP_INSTALLER_CONFIG")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);
    let (_guard, inventory) = app_manager::backup_inventory(config.as_deref())?;
    let snapshot_input = match args {
        [action, path] if matches!(action.as_str(), "verify" | "restore") => {
            let bytes = read_file(Path::new(path), MAX_ARCHIVE as u64)?;
            let stage = format!(".app-restore-{}", digest(&bytes));
            let snapshot: Snapshot = serde_json::from_slice(&bytes)?;
            Some((stage, snapshot))
        }
        _ => None,
    };
    let roots = app_roots(
        &inventory,
        snapshot_input.as_ref().map(|(name, _)| name.as_str()),
    )?;
    let empty = inventory.as_object().is_some_and(|map| map.is_empty());
    for uid in roots.keys() {
        appliance_process::verify_uid_stopped(*uid)?;
    }
    match args {
        [action] if action == "empty" && empty => Ok(()),
        [action] if action == "capture" => {
            if empty {
                return Ok(());
            }
            let mut data = BTreeMap::new();
            let mut budget = files::Budget::default();
            for (uid, path) in roots {
                data.insert(uid, files::capture(&path, uid, &mut budget)?);
            }
            let bytes = serde_json::to_vec(&Snapshot {
                format_version: 1,
                installations: inventory,
                data,
            })?;
            if bytes.len() > MAX_ARCHIVE {
                return Err(invalid("Application snapshot is too large"));
            }
            io::stdout().lock().write_all(&bytes)
        }
        [action, _] if matches!(action.as_str(), "verify" | "restore") => {
            let (stage, mut snapshot) =
                snapshot_input.ok_or_else(|| invalid("Missing app snapshot"))?;
            for (id, slot) in snapshot
                .installations
                .as_object_mut()
                .ok_or_else(|| invalid("Missing snapshot inventory"))?
            {
                let current = &inventory[id]["generation"];
                if slot["generation"]
                    .as_u64()
                    .zip(current.as_u64())
                    .is_some_and(|(old, new)| new >= old && (old == 0) == (new == 0))
                {
                    slot["generation"] = current.clone();
                }
            }
            if empty
                || snapshot.format_version != 1
                || snapshot.installations != inventory
                || snapshot.data.keys().collect::<BTreeSet<_>>() != roots.keys().collect()
            {
                return Err(invalid(
                    "Snapshot requires the same installed applications and releases",
                ));
            }
            validate_snapshot(&snapshot)?;
            let mut current_budget = files::Budget::default();
            for (uid, root) in &roots {
                files::capture(root, *uid, &mut current_budget)?;
            }
            if action == "restore" {
                for (uid, entries) in &snapshot.data {
                    files::restore(&roots[uid], *uid, entries, &stage)?;
                }
            }
            Ok(())
        }
        _ => Err(invalid(
            "Backup format cannot represent the installed applications",
        )),
    }
}

pub fn run(args: impl Iterator<Item = String>) -> ExitCode {
    match process(&args.take(3).collect::<Vec<_>>()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            eprintln!("Application backup inventory, storage or release verification failed");
            ExitCode::FAILURE
        }
    }
}
