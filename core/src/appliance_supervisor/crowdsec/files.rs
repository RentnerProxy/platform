use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use std::{
    fs::{self, File, OpenOptions, Permissions},
    io::{self, Read},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::Path,
};

use crate::protected_files::{Ownership, Publication, publish};

const CONTROL: &str = "/run/rentnerproxy/crowdsec";
const STATUS_STAGING: &str = "/run/rentnerproxy/crowdsec-supervisor";
const KEY_STAGING: &str = "/var/lib/rentnerproxy/crowdsec-supervisor";
const KEY: &str = "/var/lib/rentnerproxy/crowdsec/bouncer/caddy-bouncer-key";
const LOCAL_CREDENTIAL: &str =
    "/var/lib/rentnerproxy/crowdsec/credentials/local_api_credentials.yaml";
pub(super) const CAPI: &str =
    "/var/lib/rentnerproxy/crowdsec/credentials/online_api_credentials.yaml";
pub(super) const CONSOLE: &str = "/var/lib/rentnerproxy/crowdsec/credentials/console.yaml";

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "Invalid CrowdSec control or credential file",
    )
}

fn regular(path: &Path, uid: u32, gid: u32, mode: Option<u32>, flags: i32) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | flags)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.nlink() != 1
        || mode.is_some_and(|mode| metadata.mode() & 0o7777 != mode)
    {
        return Err(invalid());
    }
    Ok(file)
}

fn read(file: File, maximum: u64) -> io::Result<String> {
    let mut value = String::new();
    file.take(maximum + 1).read_to_string(&mut value)?;
    if value.len() as u64 > maximum {
        return Err(invalid());
    }
    Ok(value)
}

pub(super) fn desired() -> super::Mode {
    let path = Path::new(CONTROL).join("desired-mode");
    let value = regular(&path, 10001, 10001, Some(0o600), 0).and_then(|file| read(file, 32));
    match value.as_deref().map(|value| value.trim_end_matches('\n')) {
        Ok("managed") => super::Mode::Local,
        Ok("managed-online") => super::Mode::Online,
        _ => super::Mode::Stopped,
    }
}

fn shared(staging: &str, destination: &Path, bytes: &[u8]) -> io::Result<()> {
    publish(
        Path::new(staging),
        destination,
        bytes,
        Ownership {
            uid: 0,
            gid: 10001,
            mode: 0o440,
        },
        Publication::Replace,
    )
}

pub(super) fn local_credentials_present() -> io::Result<bool> {
    match fs::symlink_metadata(LOCAL_CREDENTIAL) {
        Ok(file)
            if file.is_file()
                && file.nlink() == 1
                && file.uid() == 10003
                && file.gid() == 10003 =>
        {
            Ok(file.len() > 0)
        }
        Ok(_) => Err(invalid()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

pub(super) fn registration_file() -> io::Result<tempfile::NamedTempFile> {
    let directory = Path::new(CAPI).parent().ok_or_else(invalid)?;
    let file = tempfile::Builder::new()
        .prefix(".capi-registration-")
        .tempfile_in(directory)?;
    std::os::unix::fs::fchown(file.as_file(), Some(10003), Some(10003))?;
    Ok(file)
}

pub(super) fn publish_capi(registration: &File) -> io::Result<()> {
    let contents = read(registration.try_clone()?, 65536)?;
    if contents.trim().is_empty() {
        return Err(invalid());
    }
    publish(
        Path::new(KEY_STAGING),
        Path::new(CAPI),
        contents.as_bytes(),
        Ownership {
            uid: 10003,
            gid: 10003,
            mode: 0o600,
        },
        Publication::Create,
    )
}

pub(super) fn status(name: &str, value: serde_json::Value) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(&value)?;
    bytes.push(b'\n');
    shared(STATUS_STAGING, &Path::new(CONTROL).join(name), &bytes)
}

fn generated_key(key: &[u8]) -> bool {
    key.len() == 43
        && STANDARD_NO_PAD
            .decode(key)
            .is_ok_and(|bytes| bytes.len() == 32)
}

pub(super) fn check_previous_key() -> io::Result<()> {
    match regular(Path::new(KEY), 0, 10001, Some(0o440), 0).and_then(|file| read(file, 65)) {
        Ok(contents) => {
            let key = contents.trim_end_matches('\n');
            if lower_hex(key, 64) || generated_key(key.as_bytes()) {
                Ok(())
            } else {
                Err(invalid())
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(invalid()),
    }
}

pub(super) fn publish_generated_key(mut key: Vec<u8>) -> io::Result<()> {
    if !generated_key(&key) {
        return Err(invalid());
    }
    key.push(b'\n');
    shared(KEY_STAGING, Path::new(KEY), &key)
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(super) fn enrollment_fields(text: &str) -> Option<(&str, &str)> {
    let mut fields = text.strip_suffix('\n').unwrap_or(text).split('\n');
    let (id, key) = (fields.next()?, fields.next()?);
    (fields.next().is_none()
        && lower_hex(id, 32)
        && (16..=256).contains(&key.len())
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')))
    .then_some((id, key))
}

pub(super) fn take_enrollment() -> io::Result<Option<String>> {
    let request = Path::new(CONTROL).join("console-enrollment-request");
    // Claim this exact entry in the private staging directory before reading or removing it.
    let claimed = Path::new(STATUS_STAGING).join("console-enrollment-claimed");
    if fs::symlink_metadata(&request).is_ok_and(|entry| entry.is_dir()) {
        let _ = fs::remove_dir(&request);
        return Ok(None);
    }
    match fs::rename(&request, &claimed) {
        Ok(()) => (),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    }
    let contents = regular(&claimed, 10001, 10001, Some(0o600), 0).and_then(|file| read(file, 300));
    if fs::symlink_metadata(&claimed)?.is_dir() {
        fs::remove_dir(&claimed)?;
    } else {
        fs::remove_file(&claimed)?;
    }
    match contents {
        Ok(text) if enrollment_fields(&text).is_some() => Ok(Some(text)),
        _ => {
            eprintln!("[rentnerproxy:crowdsec] invalid console enrollment request");
            Ok(None)
        }
    }
}

pub(crate) fn protect_credential(path: &Path) -> io::Result<()> {
    // Credential mutations run under the service identity and operate on the admitted descriptor.
    if unsafe { libc::geteuid() } != 10003 {
        return Err(invalid());
    }
    let file = regular(path, 10003, 10003, None, libc::O_PATH)?;
    fs::set_permissions(
        format!("/proc/self/fd/{}", file.as_raw_fd()),
        Permissions::from_mode(0o600),
    )
}
