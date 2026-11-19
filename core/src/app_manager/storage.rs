use super::{bad, journal::Slot};
use crate::app_ipc::filesystem::require_safe_parents;
use std::{
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

pub(super) fn owned(root: &Path, id: &str, slot: &Slot) -> io::Result<bool> {
    let dir = root.join(slot.uid.to_string());
    match fs::symlink_metadata(&dir) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Ok(m)
            if m.is_dir() && m.uid() == 0 && m.gid() == slot.uid && m.mode() & 0o7777 == 0o710 => {}
        _ => return Err(bad("Invalid persistent installation slot")),
    }
    require_safe_parents(&dir, 0)?;
    let marker = dir.join(OWNER);
    let meta = fs::symlink_metadata(&marker)?;
    if meta.uid() != 0
        || meta.gid() != 0
        || meta.mode() & 0o7777 != 0o400
        || marketplace_artifacts::read_file(&marker, 256)?
            != format!("{}\n{id}\n", slot.app_id).as_bytes()
    {
        return Err(bad("Persistent UID belongs to another installation"));
    }
    Ok(true)
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
    let stat = fs::symlink_metadata(root)?;
    if !stat.is_dir() || stat.uid() != 0 || stat.gid() != 0 || stat.mode() & 0o7777 != 0o711 {
        return Err(bad("Unsafe application storage root"));
    }
    File::open(parent)?.sync_all()?;
    let root_directory = File::open(root)?;
    if owned(root, id, slot)? {
        if slot.active.is_some() && slot.storage_claimed == Some(true) {
            // A committed release already used this data tree. Do not recreate it empty.
            let data = fs::symlink_metadata(directory(slot.uid).join("data"))?;
            if !data.is_dir()
                || data.uid() != slot.uid
                || data.gid() != slot.uid
                || data.mode() & 0o7777 != 0o700
            {
                return Err(bad("Invalid previously provisioned app data"));
            }
        }
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
        libc::renameat2(
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

pub(super) fn purge(id: &str, slot: &Slot) -> io::Result<()> {
    let root = Path::new(ROOT);
    let retired = root.join(format!(".purge-{}", slot.uid));
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
