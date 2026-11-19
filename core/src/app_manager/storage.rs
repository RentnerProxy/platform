use super::{bad, journal::Slot};
use crate::app_ipc::filesystem::require_safe_parents;
use std::{
    ffi::CString,
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{self as unix, DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
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
    match DirBuilder::new().mode(0o711).create(root) {
        Ok(()) => File::open(root.parent().expect("application storage parent"))?.sync_all()?,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e),
    }
    let stat = fs::symlink_metadata(root)?;
    if !stat.is_dir() || stat.uid() != 0 || stat.gid() != 0 || stat.mode() & 0o7777 != 0o711 {
        return Err(bad("Unsafe application storage root"));
    }
    if owned(root, id, slot)? {
        return Ok(());
    }
    let tmp = tempfile::Builder::new()
        .prefix(".reserve-")
        .tempdir_in(root)?;
    let marker = tmp.path().join(OWNER);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(marker)?;
    writeln!(file, "{}\n{id}", slot.app_id)?;
    file.sync_all()?;
    unix::chown(tmp.path(), Some(0), Some(slot.uid))?;
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o710))?;
    File::open(tmp.path())?.sync_all()?;
    let from = CString::new(tmp.path().as_os_str().as_bytes())?;
    let to = CString::new(directory(slot.uid).as_os_str().as_bytes())?;
    // Both names belong to the verified root-owned parent. Never replace a legacy or concurrently allocated UID.
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
    File::open(root)?.sync_all()
}

pub(super) fn purge(id: &str, slot: &Slot) -> io::Result<()> {
    let root = Path::new(ROOT);
    let retired = root.join(format!(".purge-{}", slot.uid));
    if owned(root, id, slot)? {
        let from = CString::new(directory(slot.uid).as_os_str().as_bytes())?;
        let to = CString::new(retired.as_os_str().as_bytes())?;
        // Publish a private tombstone before erasing any part of the tree, including the ownership marker.
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
        File::open(root)?.sync_all()?;
    }
    match fs::symlink_metadata(&retired) {
        Ok(meta)
            if meta.is_dir()
                && meta.uid() == 0
                && meta.gid() == slot.uid
                && meta.mode() & 0o7777 == 0o710 =>
        {
            require_safe_parents(&retired, 0)?;
            fs::remove_dir_all(retired)?;
            File::open(root)?.sync_all()?;
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
