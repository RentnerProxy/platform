use std::{
    fs::{self, DirBuilder, File, OpenOptions, TryLockError},
    io,
    path::{Component, Path},
    thread,
    time::{Duration, Instant},
};

use aws_lc_rs::digest::{Context, SHA256};
use marketplace_artifacts::{file_identity, invalid};

pub(super) fn check_root_path(path: &Path, directory: bool) -> io::Result<()> {
    if !path.is_absolute()
        || path.parent().is_none()
        || path.components().any(|part| part == Component::ParentDir)
        || path.as_os_str()
            != path
                .components()
                .collect::<std::path::PathBuf>()
                .as_os_str()
    {
        return Err(invalid("Expected an absolute normalized manager path"));
    }
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)?;
        if (ancestor != path || directory) && !metadata.is_dir()
            || ancestor == path && !directory && !metadata.is_file()
        {
            return Err(invalid("Unexpected file type in manager path"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.uid() != 0 || metadata.mode() & 0o7022 != 0 {
                return Err(invalid(
                    "Manager paths must be root-owned and protected against writes",
                ));
            }
            if directory && metadata.mode() & 0o001 == 0 {
                return Err(invalid(
                    "Application package store paths must be searchable by app identities",
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn lock(directory: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let lock = options.open(directory.join(".install.lock"))?;
    if !lock.metadata()?.is_file() {
        return Err(invalid("Invalid installer lock"));
    }
    let deadline = Instant::now() + Duration::from_millis(500);
    loop {
        match lock.try_lock() {
            Ok(()) => return Ok(lock),
            Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error.into()),
        }
    }
}

pub(super) fn directory(path: &Path, mode: u32) -> io::Result<()> {
    let parent = path.parent().expect("child directory");
    let builder = &mut DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(mode);
    }
    match builder.create(path) {
        Ok(()) => {
            permissions(path, mode)?;
            sync_directory(parent)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(path)?;
            if !metadata.is_dir() {
                return Err(invalid("Invalid installer directory"));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                let actual = metadata.mode() & 0o7777;
                if actual & !mode != 0 || metadata.uid() != unsafe { libc::geteuid() } {
                    return Err(invalid(
                        "Unexpected installer directory ownership or permissions",
                    ));
                }
                if actual != mode {
                    permissions(path, mode)?;
                    sync_directory(path)?;
                }
            }
            sync_directory(parent)
        }
        Err(error) => Err(error),
    }
}

pub(super) fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

pub(super) fn sync_file(path: &Path) -> io::Result<()> {
    OpenOptions::new().write(true).open(path)?.sync_all()
}

pub(super) fn private_workspace(parent: &Path, prefix: &str) -> io::Result<tempfile::TempDir> {
    let mut builder = tempfile::Builder::new();
    builder.prefix(prefix);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(fs::Permissions::from_mode(0o700));
    }
    builder.tempdir_in(parent)
}

/// The caller holds the store lock, and only the installer can create these workspaces.
pub(super) fn clean_workspaces(parent: &Path, prefix: &str) -> io::Result<()> {
    let mut removed = false;
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        if !entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with(prefix))
        {
            continue;
        }
        let metadata = entry.metadata()?;
        if !metadata.is_dir() {
            return Err(invalid("Invalid abandoned package workspace"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o7077 != 0 {
                return Err(invalid("Invalid abandoned package workspace"));
            }
        }
        fs::remove_dir_all(entry.path())?;
        removed = true;
    }
    if removed {
        sync_directory(parent)?;
    }
    Ok(())
}

fn permissions(path: &Path, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Ok(())
    }
}

pub(super) fn sync_tree(path: &Path) -> io::Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_dir() {
            sync_tree(&entry.path())?;
        } else if kind.is_file() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let executable = entry.metadata()?.permissions().mode() & 0o100 != 0;
                permissions(&entry.path(), if executable { 0o755 } else { 0o644 })?;
            }
            sync_file(&entry.path())?;
        } else {
            return Err(invalid(
                "Extracted package contains a special filesystem entry",
            ));
        }
    }
    permissions(path, 0o755)?;
    sync_directory(path)
}

pub(super) fn tree_digest(path: &Path) -> io::Result<[u8; 32]> {
    let mut digest = Context::new(&SHA256);
    // Each allowed USTAR entry can create implicit parents within its 240-byte path.
    let mut budget = (4096 * 121 + 1, 256 * 1024 * 1024);
    hash_tree(path, path, &mut digest, &mut budget)?;
    digest
        .finish()
        .as_ref()
        .try_into()
        .map_err(|_| invalid("Unexpected SHA-256 length"))
}

fn hash_tree(
    root: &Path,
    path: &Path,
    digest: &mut Context,
    budget: &mut (usize, u64),
) -> io::Result<()> {
    const MAX_SIBLINGS: usize = 4096;
    let invalid_tree = || invalid("Staged package differs from its verified archive");
    let relative = path.strip_prefix(root).map_err(|_| invalid_tree())?;
    let name = relative.as_os_str().as_encoded_bytes();
    if name.len() > 240 || budget.0 == 0 {
        return Err(invalid_tree());
    }
    budget.0 -= 1;
    let metadata = fs::symlink_metadata(path)?;
    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err(invalid_tree());
        }
        metadata.mode() & 0o7777
    };
    #[cfg(not(unix))]
    let mode: u32 = if metadata.is_dir() { 0o755 } else { 0o644 };
    digest.update(&(name.len() as u16).to_le_bytes());
    digest.update(name);
    digest.update(&mode.to_le_bytes());
    if metadata.is_dir() && mode == 0o755 {
        digest.update(b"d");
        let mut children = fs::read_dir(path)?
            .take(MAX_SIBLINGS + 1)
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<io::Result<Vec<_>>>()?;
        if children.len() > MAX_SIBLINGS {
            return Err(invalid_tree());
        }
        children.sort_unstable();
        for child in children {
            hash_tree(root, &path.join(child), digest, budget)?;
        }
    } else if metadata.is_file() && !name.is_empty() && matches!(mode, 0o644 | 0o755) {
        let identity = file_identity(path, budget.1)?;
        budget.1 -= identity.size_bytes;
        digest.update(b"f");
        digest.update(&identity.size_bytes.to_le_bytes());
        digest.update(identity.sha256.as_bytes());
    } else {
        return Err(invalid_tree());
    }
    Ok(())
}
