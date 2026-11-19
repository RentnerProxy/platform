use std::{
    fs::{self, File},
    io::{self, Read},
    path::Path,
    thread,
    time::{Duration, Instant},
};

const MAXIMUM_STATUS: u64 = 1_048_576;
const SCAN_BUDGET: Duration = Duration::from_secs(3);

fn is_app(uid: u32) -> bool {
    (20_000..=59_999).contains(&uid)
}

pub(crate) fn verify_uid_stopped(uid: u32) -> io::Result<()> {
    verify_writers_stopped(Path::new("/proc"), &[], |current| current == uid)
}

#[derive(Clone, Copy)]
pub(crate) enum Consumers {
    Web,
    Backup { preserve_web: bool },
}

impl Consumers {
    fn includes(self, uid: u32) -> bool {
        match self {
            Self::Web => uid == 10_002,
            Self::Backup { preserve_web } => {
                uid == 10_001 || uid == 10_003 || (!preserve_web && uid == 10_002) || is_app(uid)
            }
        }
    }
}

pub(crate) fn verify_consumers_stopped(
    consumers: Consumers,
    valkey_pid: Option<u32>,
    caddy_pid: Option<u32>,
) -> io::Result<()> {
    let exclusions = [valkey_pid.unwrap_or(0), caddy_pid.unwrap_or(0)];
    verify_writers_stopped(Path::new("/proc"), &exclusions, |uid| {
        consumers.includes(uid)
    })
}

fn verify_writers_stopped(
    proc: &Path,
    exclusions: &[u32],
    is_writer: impl Fn(u32) -> bool,
) -> io::Result<()> {
    if inspect(&proc.join("self/status"))?.is_none() {
        return Err(invalid_status());
    }
    let deadline = Instant::now() + SCAN_BUDGET;
    for entry in fs::read_dir(proc)? {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Process identity scan timed out",
            ));
        }
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
            .filter(|pid| *pid != 0 && !exclusions.contains(pid))
        else {
            continue;
        };
        let directory = proc.join(pid.to_string());
        let credentials = inspect_live_entry(&directory, deadline)?;
        if credentials.is_some_and(|uids| uids.into_iter().any(&is_writer)) {
            return Err(io::Error::other("A managed writer is still running"));
        }
    }
    Ok(())
}

fn inspect_live_entry(directory: &Path, deadline: Instant) -> io::Result<Option<[u32; 4]>> {
    let file = directory.join("status");
    for attempt in 0..3 {
        match inspect(&file) {
            Ok(credentials) => return Ok(credentials),
            Err(_)
                if fs::symlink_metadata(directory)
                    .is_err_and(|error| error.kind() == io::ErrorKind::NotFound) =>
            {
                return Ok(None);
            }
            Err(_) if attempt < 2 && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(error) => return Err(error),
        }
    }
    Err(invalid_status())
}

fn inspect(path: &Path) -> io::Result<Option<[u32; 4]>> {
    let mut status = Vec::with_capacity(2048);
    File::open(path)?
        .take(MAXIMUM_STATUS + 1)
        .read_to_end(&mut status)?;
    if status.len() as u64 > MAXIMUM_STATUS {
        return Err(invalid_status());
    }
    parse_status(&status)
}

fn parse_status(status: &[u8]) -> io::Result<Option<[u32; 4]>> {
    let state = status
        .split(|byte| *byte == b'\n')
        .find_map(|line| line.strip_prefix(b"State:"))
        .and_then(|field| {
            field
                .iter()
                .copied()
                .find(|byte| !byte.is_ascii_whitespace())
        })
        .ok_or_else(invalid_status)?;
    if matches!(state, b'Z' | b'X' | b'x') {
        return Ok(None);
    }
    let credentials = status
        .split(|byte| *byte == b'\n')
        .find_map(|line| line.strip_prefix(b"Uid:"))
        .ok_or_else(invalid_status)?;
    let credentials = std::str::from_utf8(credentials).map_err(|_| invalid_status())?;
    let mut fields = credentials.split_ascii_whitespace();
    let mut uids = [0; 4];
    for uid in &mut uids {
        *uid = fields
            .next()
            .filter(|field| field.bytes().all(|byte| byte.is_ascii_digit()))
            .and_then(|field| field.parse().ok())
            .ok_or_else(invalid_status)?;
    }
    if fields.next().is_some() {
        return Err(invalid_status());
    }
    Ok(Some(uids))
}

fn invalid_status() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "Could not read process identity",
    )
}

#[cfg(test)]
#[path = "../tests/private/appliance_process.rs"]
mod tests;
