use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io,
    path::{Component, Path},
};

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
    lock.try_lock()?;
    Ok(lock)
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

pub(super) fn compare_tree(reference: &Path, staged: &Path) -> io::Result<()> {
    let original = fs::symlink_metadata(reference)?;
    let actual = fs::symlink_metadata(staged)?;
    let mismatch = || invalid("Staged package differs from its verified archive");
    if original.file_type() != actual.file_type() {
        return Err(mismatch());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if original.mode() != actual.mode() || original.uid() != actual.uid() {
            return Err(mismatch());
        }
    }
    if original.is_dir() {
        let mut count = 0;
        for entry in fs::read_dir(reference)? {
            let entry = entry?;
            compare_tree(&entry.path(), &staged.join(entry.file_name()))?;
            count += 1;
        }
        if fs::read_dir(staged)?
            .take(count + 1)
            .collect::<Result<Vec<_>, _>>()?
            .len()
            != count
        {
            return Err(mismatch());
        }
    } else if !original.is_file()
        || original.len() != actual.len()
        || file_identity(reference, original.len())? != file_identity(staged, original.len())?
    {
        return Err(mismatch());
    }
    Ok(())
}
