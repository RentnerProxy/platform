use super::{bad, journal::Slot};
use crate::app_ipc::filesystem::require_safe_parents;
use std::{
    collections::BTreeMap,
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{self as unix, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
};

const ROOT: &str = "/var/lib/rentnerproxy/apps";
const OWNER: &str = ".manager-owner";

pub(super) fn directory(uid: u32) -> PathBuf {
    Path::new(ROOT).join(uid.to_string())
}

fn slot_directory(dir: &Path, uid: u32) -> io::Result<bool> {
    match fs::symlink_metadata(dir) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Ok(m) if m.is_dir() && m.uid() == 0 && m.gid() == uid && m.mode() & 0o7777 == 0o710 => {}
        _ => return Err(bad("Invalid persistent installation slot")),
    }
    require_safe_parents(dir, 0)?;
    Ok(true)
}

fn owner_marker(dir: &Path, id: &str, slot: &Slot) -> io::Result<()> {
    let marker = dir.join(OWNER);
    let meta = fs::symlink_metadata(&marker)?;
    if !meta.is_file()
        || meta.nlink() != 1
        || meta.uid() != 0
        || meta.gid() != 0
        || meta.mode() & 0o7777 != 0o400
        || marketplace_artifacts::read_file(&marker, 256)?
            != format!("{}\n{id}\n", slot.app_id).as_bytes()
    {
        return Err(bad("Persistent UID belongs to another installation"));
    }
    Ok(())
}

pub(super) fn owned(root: &Path, id: &str, slot: &Slot) -> io::Result<bool> {
    let dir = root.join(slot.uid.to_string());
    if !slot_directory(&dir, slot.uid)? {
        return Ok(false);
    }
    owner_marker(&dir, id, slot)?;
    Ok(true)
}

fn data_exists(dir: &Path, uid: u32) -> io::Result<bool> {
    match fs::symlink_metadata(dir.join("data")) {
        Ok(m) if m.is_dir() && m.uid() == uid && m.gid() == uid && m.mode() & 0o7777 == 0o700 => {
            Ok(true)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
        _ => Err(bad("Invalid previously provisioned app data")),
    }
}

pub(super) fn require_data(id: &str, slot: &Slot) -> io::Result<()> {
    let root = Path::new(ROOT);
    validate_root(root)?;
    if !owned(root, id, slot)? || !data_exists(&directory(slot.uid), slot.uid)? {
        return Err(bad("Previously provisioned app data is missing"));
    }
    Ok(())
}

#[derive(Debug)]
pub(super) struct CommittedDataUnavailable(pub io::Error);

impl std::fmt::Display for CommittedDataUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Cannot start with unavailable committed data: {}",
            self.0
        )
    }
}

impl std::error::Error for CommittedDataUnavailable {}

fn validate_root(root: &Path) -> io::Result<()> {
    require_safe_parents(root, 0)?;
    let stat = fs::symlink_metadata(root)?;
    if !stat.is_dir() || stat.uid() != 0 || stat.gid() != 0 || stat.mode() & 0o7777 != 0o711 {
        return Err(bad("Unsafe application storage root"));
    }
    Ok(())
}

pub(super) fn claim(id: &str, slot: &Slot) -> io::Result<()> {
    let root = Path::new(ROOT);
    require_safe_parents(root, 0)?;
    let parent = root.parent().expect("application storage parent");
    match fs::symlink_metadata(root) {
        Ok(_) => (),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let tmp = tempfile::Builder::new()
                .prefix(".apps-")
                .tempdir_in(parent)?;
            unix::chown(tmp.path(), Some(0), Some(0))?;
            fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o711))?;
            File::open(tmp.path())?.sync_all()?;
            match rename_new(tmp.path(), root) {
                Ok(()) => (),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (),
                Err(e) => return Err(e),
            }
        }
        Err(e) => return Err(e),
    }
    validate_root(root)?;
    File::open(parent)?.sync_all()?;
    let root_directory = File::open(root)?;
    if owned(root, id, slot)? {
        return root_directory.sync_all();
    }
    if slot.storage_claimed == Some(true) {
        return Err(bad("Previously claimed installation storage is missing"));
    }
    // A power loss may leave a reservation behind. Keep it outside the scanned app inventory.
    let tmp = tempfile::Builder::new()
        .prefix(".reserve-")
        .tempdir_in(parent)?;
    let marker = tmp.path().join(OWNER);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(marker)?;
    writeln!(file, "{}\n{id}", slot.app_id)?;
    unix::fchown(&file, Some(0), Some(0))?;
    file.set_permissions(fs::Permissions::from_mode(0o400))?;
    file.sync_all()?;
    unix::chown(tmp.path(), Some(0), Some(slot.uid))?;
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o710))?;
    File::open(tmp.path())?.sync_all()?;
    rename_new(tmp.path(), &directory(slot.uid))?;
    File::open(parent)?.sync_all()?;
    root_directory.sync_all()
}

fn rename_new(from: &Path, to: &Path) -> io::Result<()> {
    let from = CString::new(from.as_os_str().as_bytes())?;
    let to = CString::new(to.as_os_str().as_bytes())?;
    // Both names belong to a verified root-owned parent. Preserve an existing destination.
    if unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

const PROVISION_LOCK: &str = ".provision.lock";

// The writer fence excludes the provisioner. Never recurse into a first-claim reservation.
fn check_empty_reservation(dir: &Path, id: &str, slot: &Slot) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_name() == OWNER {
            owner_marker(dir, id, slot)?;
        } else if entry.file_name() == PROVISION_LOCK {
            let m = fs::symlink_metadata(entry.path())?;
            if !m.is_file()
                || m.nlink() != 1
                || m.uid() != 0
                || m.gid() != 0
                || m.mode() & 0o7777 != 0o600
                || m.len() != 0
            {
                return Err(bad("Invalid application provision lock"));
            }
        } else {
            return Err(bad("Unexpected file in interrupted storage reservation"));
        }
    }
    Ok(())
}

fn unclaim_path(uid: u32) -> PathBuf {
    Path::new(ROOT).join(format!(".unclaim-{uid}"))
}

pub(super) fn reconcile_first_claim(id: &str, slot: &Slot) -> io::Result<bool> {
    let root = Path::new(ROOT);
    require_safe_parents(root, 0)?;
    if slot.storage_claimed != Some(true)
        && fs::symlink_metadata(root).is_err_and(|e| e.kind() == io::ErrorKind::NotFound)
    {
        return Ok(false);
    }
    validate_root(root)?;
    let dir = directory(slot.uid);
    let retired = unclaim_path(slot.uid);
    if owned(root, id, slot)? {
        if slot.storage_claimed == Some(false) || slot_directory(&retired, slot.uid)? {
            return Err(bad("Conflicting first storage claim"));
        }
        if data_exists(&dir, slot.uid)? {
            return Ok(true);
        }
        check_empty_reservation(&dir, id, slot)?;
        rename_new(&dir, &retired)?;
    } else if slot_directory(&retired, slot.uid)? {
        // Until the journal acknowledges the rename, cleanup cannot have removed the marker.
        if slot.storage_claimed != Some(false) {
            owner_marker(&retired, id, slot)?;
        }
        check_empty_reservation(&retired, id, slot)?;
    } else if slot.storage_claimed == Some(true) {
        return Err(bad("Previously claimed installation storage is missing"));
    }
    // The rename is durable before the journal records that no user data exists.
    File::open(root)?.sync_all()?;
    Ok(false)
}

pub(super) fn finish_unclaim(id: &str, slot: &Slot) -> io::Result<()> {
    let retired = unclaim_path(slot.uid);
    if slot_directory(&retired, slot.uid)? {
        check_empty_reservation(&retired, id, slot)?;
        for name in [PROVISION_LOCK, OWNER] {
            match fs::remove_file(retired.join(name)) {
                Err(e) if e.kind() == io::ErrorKind::NotFound => (),
                result => result?,
            }
        }
        fs::remove_dir(&retired)?;
    }
    // A previous attempt may have removed the directory and failed its final sync.
    match File::open(ROOT) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result?.sync_all(),
    }
}

fn purge_path(uid: u32) -> PathBuf {
    Path::new(ROOT).join(format!(".purge-{uid}"))
}

fn retired_uid(name: &str) -> Option<u32> {
    let digits = name
        .strip_prefix(".purge-")
        .or_else(|| name.strip_prefix(".unclaim-"))
        .unwrap_or(name);
    digits
        .parse::<u32>()
        .ok()
        .filter(|uid| uid.to_string() == digits)
}

/// Checks, and with `apply` removes, the persistent storage of every journal
/// installation that a portable restore replaces. Storage of any other UID is
/// never removed: its presence rejects the restore before anything changes.
pub(super) fn retire(slots: &BTreeMap<String, Slot>, apply: bool) -> io::Result<()> {
    let root = Path::new(ROOT);
    require_safe_parents(root, 0)?;
    match fs::symlink_metadata(root) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
        Ok(_) => validate_root(root)?,
    }
    let owners: BTreeMap<u32, (&str, &Slot)> = slots
        .iter()
        .map(|(id, slot)| (slot.uid, (id.as_str(), slot)))
        .collect();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let (uid, (id, slot)) = entry
            .file_name()
            .to_str()
            .and_then(retired_uid)
            .and_then(|uid| owners.get_key_value(&uid))
            .ok_or_else(|| bad("Untracked installation data"))?;
        if !slot_directory(&entry.path(), *uid)? {
            return Err(bad("Invalid persistent installation slot"));
        }
        // Interrupted purges and unclaims are already detached from their owner.
        if entry.path() == directory(*uid) {
            owner_marker(&entry.path(), id, slot)?;
        }
    }
    if !apply {
        return Ok(());
    }
    let parent = File::open(root)?;
    for (&uid, &(id, slot)) in &owners {
        let tombstone = purge_path(uid);
        for detached in [&tombstone, &unclaim_path(uid)] {
            if slot_directory(detached, uid)? {
                fs::remove_dir_all(detached)?;
                parent.sync_all()?;
            }
        }
        // Detach the tree before erasing it so an interrupted retry never sees a
        // live slot without its ownership marker.
        if owned(root, id, slot)? {
            rename_new(&directory(uid), &tombstone)?;
            parent.sync_all()?;
            fs::remove_dir_all(&tombstone)?;
            parent.sync_all()?;
        }
    }
    Ok(())
}

pub(super) fn purge(id: &str, slot: &Slot) -> io::Result<()> {
    let root = Path::new(ROOT);
    let retired = purge_path(slot.uid);
    if owned(root, id, slot)? {
        // Publish a private tombstone before erasing any part of the tree, including the ownership marker.
        rename_new(&directory(slot.uid), &retired)?;
    }
    match fs::symlink_metadata(&retired) {
        Ok(meta)
            if meta.is_dir()
                && meta.uid() == 0
                && meta.gid() == slot.uid
                && meta.mode() & 0o7777 == 0o710 =>
        {
            require_safe_parents(&retired, 0)?;
            let root_directory = File::open(root)?;
            root_directory.sync_all()?;
            fs::remove_dir_all(retired)?;
            root_directory.sync_all()?;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            match OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
                .open(root)
            {
                Ok(directory) => directory.sync_all()?,
                Err(e) if e.kind() == io::ErrorKind::NotFound => (),
                Err(e) => return Err(e),
            }
        }
        _ => return Err(bad("Unexpected data purge tombstone")),
    }
    Ok(())
}
