use aws_lc_rs::rand::{SecureRandom, SystemRandom};
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
pub(super) const CAPI: &str =
    "/var/lib/rentnerproxy/crowdsec/credentials/online_api_credentials.yaml";
pub(super) const CONSOLE: &str = "/var/lib/rentnerproxy/crowdsec/credentials/console.yaml";

fn invalid() -> io::Error {
    io::Error::other("Invalid CrowdSec control or credential file")
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

pub(super) fn status(name: &str, value: serde_json::Value) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(&value)?;
    bytes.push(b'\n');
    shared(STATUS_STAGING, &Path::new(CONTROL).join(name), &bytes)
}

pub(super) fn key() -> io::Result<String> {
    let value = read(regular(Path::new(KEY), 0, 10001, Some(0o440), 0)?, 65)?;
    let key = value.trim_end_matches('\n');
    if !lower_hex(key, 64) {
        return Err(invalid());
    }
    Ok(key.to_owned())
}

pub(super) fn rotate_key() -> io::Result<()> {
    match key() {
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
        _ => (),
    }
    let mut random = [0; 32];
    SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| io::Error::other("Random source unavailable"))?;
    let mut hex = String::with_capacity(65);
    for byte in random {
        use std::fmt::Write;
        write!(hex, "{byte:02x}").expect("writing to String");
    }
    hex.push('\n');
    shared(KEY_STAGING, Path::new(KEY), hex.as_bytes())
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
