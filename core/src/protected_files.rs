use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, fchown},
    path::Path,
    process::ExitCode,
};

#[derive(Clone, Copy)]
pub(crate) struct Ownership {
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) mode: u32,
}

#[derive(Clone, Copy)]
pub(crate) enum Publication {
    Create,
    Replace,
}

/// Called with an already admitted staging directory and destination parent.
pub(crate) fn publish(
    staging_directory: &Path,
    destination: &Path,
    contents: &[u8],
    ownership: Ownership,
    publication: Publication,
) -> io::Result<()> {
    let directory = destination.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "Missing destination directory")
    })?;
    let parent = open_directory(directory)?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".rentnerproxy-private-")
        .tempfile_in(staging_directory)?;
    temporary.write_all(contents)?;
    fchown(
        temporary.as_file(),
        Some(ownership.uid),
        Some(ownership.gid),
    )?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(ownership.mode))?;
    temporary.as_file().sync_all()?;
    match publication {
        Publication::Create => temporary.persist_noclobber(destination),
        Publication::Replace => temporary.persist(destination),
    }
    .map_err(|error| error.error)?;
    parent.sync_all()?;
    if directory != staging_directory {
        open_directory(staging_directory)?.sync_all()?;
    }
    Ok(())
}

fn open_directory(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
}

const BOOTSTRAP: &str = "/var/lib/rentnerproxy/bootstrap";
const MAXIMUM_STATE_BYTES: u64 = 4_096;

pub fn run_write_bootstrap_state(mut arguments: impl Iterator<Item = String>) -> ExitCode {
    let file = arguments.next();
    let publication = match arguments.next().as_deref() {
        Some("create") => Some(Publication::Create),
        Some("replace") => Some(Publication::Replace),
        _ => None,
    };
    if let (Some(file), Some(publication), None) = (file, publication, arguments.next())
        && write_bootstrap_state(&file, publication, io::stdin().lock()).is_ok()
    {
        return ExitCode::SUCCESS;
    }
    eprintln!("Unable to publish protected bootstrap state");
    ExitCode::FAILURE
}

fn write_bootstrap_state(name: &str, publication: Publication, input: impl Read) -> io::Result<()> {
    if !matches!(
        name,
        "secrets-v1.json" | "app-key-restore-v1.json" | "production-restore-v1.json"
    ) {
        return Err(unsafe_state());
    }
    // SAFETY: geteuid reports only this process's credentials.
    if unsafe { libc::geteuid() } != 0 {
        return Err(unsafe_state());
    }
    let directory = Path::new(BOOTSTRAP);
    let destination = directory.join(name);
    crate::app_ipc::filesystem::require_safe_parents(&destination, 0)?;
    let parent = open_directory(directory)?.metadata()?;
    if parent.uid() != 0 || parent.mode() & 0o077 != 0 {
        return Err(unsafe_state());
    }

    match fs::symlink_metadata(&destination) {
        Ok(existing) => {
            if !existing.is_file()
                || existing.uid() != 0
                || existing.nlink() != 1
                || existing.mode() & 0o7777 != 0o400
            {
                return Err(unsafe_state());
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    let mut contents = Vec::new();
    input
        .take(MAXIMUM_STATE_BYTES + 1)
        .read_to_end(&mut contents)?;
    if contents.is_empty() || contents.len() as u64 > MAXIMUM_STATE_BYTES || contents.contains(&0) {
        return Err(unsafe_state());
    }
    publish(
        directory,
        &destination,
        &contents,
        Ownership {
            uid: 0,
            gid: 0,
            mode: 0o400,
        },
        publication,
    )
}

fn unsafe_state() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "Unsafe bootstrap state")
}

#[cfg(test)]
#[path = "../tests/private/protected_files.rs"]
mod tests;
