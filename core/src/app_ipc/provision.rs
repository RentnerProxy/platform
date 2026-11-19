mod database;

use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Read},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt, fchown},
    path::Path,
    process::ExitCode,
};

use super::filesystem::{lock_file, require_safe_parents};
use crate::protected_files::{Ownership, Publication, publish};

const APPLICATIONS: &str = "/var/lib/rentnerproxy/apps";
const PASSWORD_FILE: &str = "database-password";

#[derive(Clone, Copy)]
pub(super) enum Storage {
    Files,
    Database,
}

pub(super) async fn provision(uid: u32, storage: Storage) -> io::Result<()> {
    // SAFETY: geteuid reads process credentials without borrowing memory.
    if unsafe { libc::geteuid() } != 0 || !(20_000..=59_999).contains(&uid) {
        return Err(unsafe_path());
    }
    let root = Path::new(APPLICATIONS);
    require_safe_parents(root, 0)?;
    let applications = ensure_directory(root, 0, 0, 0o711)?;
    lock_file(&applications)?;
    let installation = root.join(uid.to_string());
    ensure_directory(&installation, 0, uid, 0o710)?;
    drop(applications);

    let _lock = provision_lock(&installation)?;
    let data = installation.join("data");
    ensure_directory(&data, uid, uid, 0o700)?;
    if let Storage::Database = storage {
        let password = database_password(&installation)?;
        let role = database::create(uid, &password).await?;
        let url = format!(
            "postgresql://{role}:{password}@localhost/{role}?socket=/run/rentnerproxy/app-db&max=4\n"
        );
        publish(
            &installation,
            &data.join("database-url"),
            url.as_bytes(),
            Ownership {
                uid,
                gid: uid,
                mode: 0o400,
            },
            Publication::Replace,
        )?;
    }
    Ok(())
}

pub async fn run_app_provision(mut arguments: impl Iterator<Item = String>) -> ExitCode {
    let uid = arguments.next().and_then(|uid| {
        (uid.len() == 5 && uid.bytes().all(|byte| byte.is_ascii_digit()))
            .then(|| uid.parse::<u32>().ok())
            .flatten()
    });
    let storage = match arguments.next().as_deref() {
        None | Some("files") => Some(Storage::Files),
        Some("database") => Some(Storage::Database),
        _ => None,
    };
    if let (Some(uid), Some(storage), None) = (uid, storage, arguments.next())
        && provision(uid, storage).await.is_ok()
    {
        return ExitCode::SUCCESS;
    }
    eprintln!("Could not provision the application identity");
    ExitCode::FAILURE
}

fn ensure_directory(path: &Path, uid: u32, gid: u32, mode: u32) -> io::Result<File> {
    match DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)?;
    let stat = directory.metadata()?;
    if stat.uid() == uid && stat.gid() == gid && stat.mode() & 0o7777 == mode {
        return Ok(directory);
    }
    if stat.uid() == 0 && (stat.gid() == 0 || stat.gid() == gid) && stat.mode() & 0o7777 == 0o700 {
        fchown(&directory, Some(uid), Some(gid))?;
        directory.set_permissions(fs::Permissions::from_mode(mode))?;
        directory.sync_all()?;
        File::open(path.parent().ok_or_else(unsafe_path)?)?.sync_all()?;
        return Ok(directory);
    }
    Err(unsafe_path())
}

fn provision_lock(installation: &Path) -> io::Result<File> {
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(installation.join(".provision.lock"))?;
    require_root_file(&lock.metadata()?, 0o600)?;
    lock_file(&lock)?;
    Ok(lock)
}

fn database_password(installation: &Path) -> io::Result<String> {
    let path = installation.join(PASSWORD_FILE);
    let publication = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
    {
        Ok(file) => {
            if let Some(password) = read_password(file)? {
                return Ok(password);
            }
            Publication::Replace
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Publication::Create,
        Err(error) => return Err(error),
    };
    let password = new_password()?;
    let mut contents = password.as_bytes().to_vec();
    contents.push(b'\n');
    publish(
        installation,
        &path,
        &contents,
        Ownership {
            uid: 0,
            gid: 0,
            mode: 0o600,
        },
        publication,
    )?;
    Ok(password)
}

fn read_password(file: File) -> io::Result<Option<String>> {
    let metadata = file.metadata()?;
    if metadata.mode() & 0o7777 == 0o400 {
        require_root_file(&metadata, 0o400)?;
    } else {
        require_root_file(&metadata, 0o600)?;
    }
    let mut password = String::new();
    file.take(66).read_to_string(&mut password)?;
    if password.is_empty() {
        return Ok(None);
    }
    if password.ends_with('\n') {
        password.pop();
    }
    if password.len() != 64
        || !password
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(io::Error::other(
            "Invalid protected app database credential",
        ));
    }
    Ok(Some(password))
}

fn new_password() -> io::Result<String> {
    let mut random = [0_u8; 32];
    aws_lc_rs::rand::fill(&mut random)
        .map_err(|_| io::Error::other("Could not generate an app database credential"))?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut password = String::with_capacity(64);
    for byte in random {
        password.push(char::from(HEX[usize::from(byte >> 4)]));
        password.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(password)
}

fn require_root_file(metadata: &fs::Metadata, mode: u32) -> io::Result<()> {
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o7777 != mode
    {
        return Err(unsafe_path());
    }
    Ok(())
}

fn unsafe_path() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "Invalid application storage ownership",
    )
}
