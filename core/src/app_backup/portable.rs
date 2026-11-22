mod database;
mod envelope;

use super::{APPS, checked_app_roots, files, storage_requirement};
use crate::{
    app_install::{Installer, filesystem},
    app_ipc::filesystem::require_safe_parents,
    app_manager::portable_backup::{BackupJournal, Destination, Inventory, provision_database},
};
use envelope::{Kind, Member};
use marketplace_artifacts::{file_identity, invalid};
use serde_json::Value;
use std::{collections::BTreeMap, fs::File, io, path::Path};

const APPLIANCE: &str = "/var/lib/rentnerproxy";

pub(super) fn capture() -> io::Result<()> {
    let journal = BackupJournal::open()?;
    let inventory = journal.capture()?;
    let _writers = inventory.lock_writers(&journal, false)?;
    let roots = checked_app_roots(Path::new(APPS), &inventory.metadata()?, None, true)?;
    if inventory.is_empty() {
        return Ok(());
    }
    let databases = inventory.databases();
    database::verify_inventory(&databases)?;
    let scratch = scratch()?;
    let data_path = scratch.path().join("app-files.json");
    let mut data = BTreeMap::new();
    let mut budget = files::Budget::default();
    for (uid, root) in roots {
        let database = databases.binary_search(&uid).is_ok();
        data.insert(
            uid,
            files::capture_files(&root, uid, &mut budget, database)?,
        );
    }
    validate_data(&inventory, &data)?;
    serde_json::to_writer(File::create(&data_path)?, &data)?;
    drop(data);
    let mut members = vec![(
        Member::new(
            Kind::Data,
            "files".into(),
            file_identity(&data_path, envelope::MAX_FILE_DATA)?,
        ),
        data_path,
    )];

    let packages = inventory.package_digests();
    let installer = (!packages.is_empty()).then(installer).transpose()?;
    // The installer lock protects the catalog and compressed archives until the
    // last byte leaves stdout. The manager and per-app writer locks pin file data.
    let source = installer
        .as_ref()
        .map(Installer::recovery_source)
        .transpose()?;
    if let Some(source) = &source {
        inventory.verify_packages(|id, version, digest| source.recover(id, version, digest))?;
        let path = source.checkpoint_path();
        let identity = file_identity(&path, Member::limit(Kind::Checkpoint))?;
        members.push((
            Member::new(Kind::Checkpoint, "catalog".into(), identity),
            path,
        ));
        for digest in packages {
            let path = source.archive_path(digest)?;
            let identity = file_identity(&path, Member::limit(Kind::Package))?;
            members.push((Member::new(Kind::Package, digest.into(), identity), path));
        }
    }
    for uid in databases {
        let path = scratch.path().join(uid.to_string());
        database::capture(uid, &path)?;
        let identity = file_identity(&path, Member::limit(Kind::Database))?;
        members.push((Member::new(Kind::Database, uid.to_string(), identity), path));
    }
    envelope::write(inventory, members, io::stdout().lock())
}

pub(super) fn inspect(input: &Path) -> io::Result<()> {
    envelope::read(input, None).map(drop)
}

pub(super) fn recover(input: &Path, apply: bool) -> io::Result<()> {
    let mut journal = BackupJournal::open()?;
    let scratch = scratch()?;
    let backup = envelope::read(input, Some(scratch.path()))?;
    let destination = journal.destination(&backup.digest, &backup.inventory)?;
    let fresh = destination == Destination::Fresh;
    let writers = backup.inventory.lock_writers(&journal, fresh)?;
    let metadata = if fresh {
        Value::Object(Default::default())
    } else {
        backup.inventory.metadata()?
    };
    let stage = format!(".app-restore-{}", backup.digest);
    let resume_stage = (destination == Destination::Resuming).then_some(stage.as_str());
    let roots = checked_app_roots(Path::new(APPS), &metadata, resume_stage, true)?;
    if roots.keys().any(|uid| !backup.data.contains_key(uid)) {
        return Err(invalid(
            "Target app storage does not match the recovery inventory",
        ));
    }
    files::inspect_targets(&roots, &backup.data, &mut 0)?;
    let installer = backup
        .checkpoint
        .as_ref()
        .map(|_| installer())
        .transpose()?;
    let packages = installer
        .as_ref()
        .zip(backup.checkpoint.as_deref())
        .map(|(installer, checkpoint)| installer.prepare_recovery(checkpoint, &backup.packages))
        .transpose()?;
    if let Some(packages) = &packages {
        backup
            .inventory
            .verify_packages(|id, version, digest| packages.recover(id, version, digest))?;
    }
    for (&uid, path) in &backup.databases {
        database::verify_archive(uid, path)?;
    }
    if !apply {
        return Ok(());
    }

    match destination {
        Destination::Fresh => {
            database::verify_inventory(&[])?;
            journal.begin(&backup.digest)?;
        }
        Destination::Resuming => {
            for &uid in backup.databases.keys() {
                database::reset(uid)?;
            }
            database::verify_inventory(&[])?;
        }
        Destination::Published => {
            database::verify_inventory(&backup.inventory.databases())?;
            return journal.finish(&backup.digest, backup.inventory);
        }
    }
    let mut outgoing_nodes = 0;
    for (&uid, data) in &backup.data {
        let root = backup.inventory.claim_storage(uid)?;
        let target = files::inspect_target(&root, uid, &mut outgoing_nodes)?;
        files::restore(&root, uid, data, &stage, target)?;
    }
    if !backup.databases.is_empty() {
        let provisioner = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        for (&uid, dump) in &backup.databases {
            provisioner.block_on(provision_database(uid, &writers[&uid]))?;
            database::restore(uid, dump)?;
        }
    }
    database::verify_inventory(&backup.inventory.databases())?;
    if let Some(packages) = packages {
        packages.publish()?;
    }
    journal.finish(&backup.digest, backup.inventory)
}

fn validate_data(inventory: &Inventory, data: &BTreeMap<u32, Vec<files::Entry>>) -> io::Result<()> {
    let metadata = inventory.metadata()?;
    let databases = inventory.databases();
    let slots = metadata
        .as_object()
        .ok_or_else(|| invalid("Invalid recovery inventory"))?;
    let mut remaining = data.len();
    for slot in slots.values() {
        let uid = slot["uid"]
            .as_u64()
            .ok_or_else(|| invalid("Missing recovery UID"))? as u32;
        let present = data.contains_key(&uid);
        if storage_requirement(slot)?.is_some_and(|required| required != present)
            || (databases.binary_search(&uid).is_ok() && !present)
        {
            return Err(invalid(
                "Application file data differs from the recovery inventory",
            ));
        }
        remaining -= usize::from(present);
    }
    if remaining != 0 {
        return Err(invalid("Unexpected application file data"));
    }
    let mut budget = files::Budget::default();
    for (&uid, entries) in data {
        files::validate_files(entries, &mut budget, databases.binary_search(&uid).is_ok())?;
    }
    Ok(())
}

fn installer() -> io::Result<Installer> {
    Installer::open_appliance(Installer::appliance_override().as_deref())
}

fn scratch() -> io::Result<tempfile::TempDir> {
    const PREFIX: &str = ".portable-app-backup-";
    let appliance = Path::new(APPLIANCE);
    require_safe_parents(&appliance.join(".portable-app-backup"), 0)?;
    // Both capture and restore hold the exclusive manager journal lock.
    filesystem::clean_workspaces(appliance, PREFIX)?;
    filesystem::private_workspace(appliance, PREFIX)
}
