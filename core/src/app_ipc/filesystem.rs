use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{
            self as unix_fs, DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt,
            PermissionsExt,
        },
    },
    path::{Component, Path, PathBuf},
};

use hyper::header::HeaderValue;
use tokio::net::{UnixListener, UnixStream};

use super::LaunchConfig;

const CONTROLLER_UID: u32 = 10001;

fn invalid_path() -> io::Error {
    io::Error::other("Unsafe application runtime path or ownership")
}

fn require_safe_parents(path: &Path, trusted_uid: u32) -> io::Result<()> {
    let normalized: PathBuf = path.components().collect();
    if !path.is_absolute() || path.as_os_str() != normalized.as_os_str() {
        return Err(invalid_path());
    }
    let mut parent = PathBuf::from("/");
    for component in path.parent().ok_or_else(invalid_path)?.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => parent.push(name),
            _ => return Err(invalid_path()),
        }
        let metadata = fs::symlink_metadata(&parent)?;
        if !metadata.is_dir()
            || (metadata.uid() != 0 && metadata.uid() != trusted_uid)
            || metadata.mode() & 0o022 != 0
        {
            return Err(invalid_path());
        }
    }
    if !matches!(path.components().next_back(), Some(Component::Normal(_))) {
        return Err(invalid_path());
    }
    Ok(())
}

pub(super) fn validate_child_paths(config: &LaunchConfig) -> io::Result<()> {
    require_safe_parents(&config.executable, 0)?;
    let executable = fs::symlink_metadata(&config.executable)?;
    if !executable.is_file()
        || executable.uid() != 0
        || executable.mode() & 0o7022 != 0
        || executable.mode() & 0o001 == 0
    {
        return Err(invalid_path());
    }
    require_safe_parents(&config.data_directory, 0)?;
    let data = fs::symlink_metadata(&config.data_directory)?;
    if !data.is_dir()
        || data.uid() != config.uid
        || data.gid() != config.gid
        || data.mode() & 0o7777 != 0o700
    {
        return Err(invalid_path());
    }
    if let Some(path) = &config.database_url_file {
        if path.parent() != Some(&config.data_directory) {
            return Err(invalid_path());
        }
        let file = fs::symlink_metadata(path)?;
        if !file.is_file()
            || file.uid() != config.uid
            || file.gid() != config.gid
            || file.nlink() != 1
            || file.mode() & 0o7077 != 0
        {
            return Err(invalid_path());
        }
    }
    Ok(())
}

pub(super) fn bridge_authorization(path: &Path) -> io::Result<HeaderValue> {
    require_safe_parents(path, CONTROLLER_UID)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || !matches!(metadata.uid(), 0 | CONTROLLER_UID)
        || !matches!(metadata.gid(), 0 | super::WEB_UID)
        || metadata.mode() & 0o7137 != 0
        || metadata.nlink() != 1
    {
        return Err(io::Error::other("Unsafe protected controller token file"));
    }
    let mut token = String::new();
    file.take(4097).read_to_string(&mut token)?;
    let token = token.trim();
    if token.is_empty() || token.len() > 4096 || token.bytes().any(|byte| !byte.is_ascii_graphic())
    {
        return Err(io::Error::other("Invalid protected controller token file"));
    }
    let mut header = HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|_| io::Error::other("Invalid protected controller token file"))?;
    header.set_sensitive(true);
    Ok(header)
}

pub(super) struct GenerationSockets {
    root: PathBuf,
    pub(super) core_socket: PathBuf,
    pub(super) app_socket: PathBuf,
}

impl GenerationSockets {
    pub(super) fn bind(root: &Path, config: &LaunchConfig) -> io::Result<(Self, UnixListener)> {
        require_safe_parents(root, 0)?;
        create_checked_directory(root, 0, 0o711)?;
        let uid_root = root.join(config.uid.to_string());
        create_checked_directory(&uid_root, config.gid, 0o710)?;
        reserve_uid(&uid_root, config)?;
        let root = uid_root.join(config.generation.to_string());
        let app_directory = root.join("app");
        let core_socket = root.join("core.sock");
        let app_socket = app_directory.join("app.sock");
        if !valid_socket_path(&core_socket) || !valid_socket_path(&app_socket) {
            return Err(invalid_path());
        }

        // Only this manager may create entries in the generation directory.
        DirBuilder::new().mode(0o700).create(&root)?;
        let sockets = Self {
            root,
            core_socket,
            app_socket,
        };
        DirBuilder::new().mode(0o700).create(&app_directory)?;
        unix_fs::chown(&app_directory, Some(config.uid), Some(config.gid))?;
        let listener = UnixListener::bind(&sockets.core_socket)?;
        unix_fs::chown(&sockets.core_socket, Some(0), Some(config.gid))?;
        fs::set_permissions(&sockets.core_socket, fs::Permissions::from_mode(0o660))?;
        unix_fs::chown(&sockets.root, Some(0), Some(config.gid))?;
        fs::set_permissions(&sockets.root, fs::Permissions::from_mode(0o710))?;
        Ok((sockets, listener))
    }
}

impl Drop for GenerationSockets {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.core_socket);
        let _ = fs::remove_file(&self.app_socket);
        let _ = fs::remove_dir(self.root.join("app"));
        let _ = fs::remove_dir(&self.root);
    }
}

fn valid_socket_path(path: &Path) -> bool {
    path.to_str().is_some_and(|path| {
        path.len() <= 107
            && path.strip_prefix('/').is_some_and(|path| {
                path.split('/').all(|component| {
                    component.split('.').all(|part| {
                        !part.is_empty()
                            && part.bytes().all(|byte| {
                                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
                            })
                    })
                })
            })
    })
}

fn create_checked_directory(path: &Path, gid: u32, mode: u32) -> io::Result<()> {
    // Serialize initial ownership/mode changes through the new directory's own lock.
    match DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    };
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)?;
    lock_file(&directory)?;
    let metadata = directory.metadata()?;
    if metadata.uid() != 0 {
        return Err(invalid_path());
    }
    if metadata.gid() == 0 && metadata.mode() & 0o7777 == 0o700 {
        unix_fs::chown(path, Some(0), Some(gid))?;
        directory.set_permissions(fs::Permissions::from_mode(mode))?;
    } else if metadata.gid() != gid || metadata.mode() & 0o7777 != mode {
        return Err(invalid_path());
    }
    Ok(())
}

fn lock_file(file: &File) -> io::Result<()> {
    // SAFETY: The file owns a valid descriptor throughout flock.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn reserve_uid(path: &Path, config: &LaunchConfig) -> io::Result<()> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)?;
    lock_file(&directory)?;
    // This path is protected by the root-owned directory and the allocation lock.
    let identity_path = path.join("identity");
    let expected = format!("{}\n{}\n", config.app_id, config.installation_id);
    let mut identity = String::new();
    match File::open(&identity_path) {
        Ok(file) => {
            file.take(256).read_to_string(&mut identity)?;
            if identity != expected {
                return Err(io::Error::other(
                    "App UID is assigned to a different installation",
                ));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(identity_path)?
                .write_all(expected.as_bytes())?;
        }
        Err(error) => return Err(error),
    }
    Ok(())
}

pub(super) async fn connect_peer(path: &Path, uid: u32) -> io::Result<UnixStream> {
    let socket = fs::symlink_metadata(path)?;
    if !socket.file_type().is_socket() || socket.uid() != uid {
        return Err(invalid_path());
    }
    let stream = UnixStream::connect(path).await?;
    if stream.peer_cred()?.uid() != uid {
        return Err(io::Error::other("Unix socket peer UID mismatch"));
    }
    Ok(stream)
}
