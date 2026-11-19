use std::{
    collections::HashSet,
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

pub(crate) fn uid_in_use(uid: u32) -> io::Result<bool> {
    writers_present(Path::new("/proc"), &[], |current| current == uid)
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
    if writers_present(proc, exclusions, is_writer)? {
        return Err(io::Error::other("A managed writer is still running"));
    }
    Ok(())
}

fn writers_present(
    proc: &Path,
    exclusions: &[u32],
    is_writer: impl Fn(u32) -> bool,
) -> io::Result<bool> {
    if inspect(&proc.join("self/status"))?.uids.is_none() {
        return Err(invalid_status());
    }
    let deadline = Instant::now() + SCAN_BUDGET;
    scan_tasks(proc, exclusions, deadline, &is_writer, None)
}

fn scan_tasks(
    directory: &Path,
    exclusions: &[u32],
    deadline: Instant,
    is_writer: &impl Fn(u32) -> bool,
    expected_threads: Option<u32>,
) -> io::Result<bool> {
    check_deadline(deadline)?;
    let entries = fs::read_dir(directory)?;
    let mut observed = 0;
    for entry in entries {
        check_deadline(deadline)?;
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|pid| *pid != 0 && !exclusions.contains(pid))
        else {
            continue;
        };
        observed += 1;
        let process = directory.join(pid.to_string());
        let Some(task) = inspect_live_entry(&process, deadline)? else {
            continue;
        };
        if task
            .uids
            .is_some_and(|uids| uids.into_iter().any(is_writer))
        {
            return Ok(true);
        }
        if expected_threads.is_none() && (task.threads > 1 || task.uids.is_none()) {
            let siblings = scan_tasks(
                &process.join("task"),
                &[],
                deadline,
                is_writer,
                Some(task.threads),
            );
            let present = match siblings {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
                    ) =>
                {
                    match hidden_group_has_writer(
                        directory,
                        Path::new("/sys/fs/cgroup"),
                        pid,
                        deadline,
                        is_writer,
                    ) {
                        Err(error)
                            if error.kind() == io::ErrorKind::NotFound && disappeared(&process) =>
                        {
                            false
                        }
                        result => result?,
                    }
                }
                result => result?,
            };
            if present {
                return Ok(true);
            }
        }
    }
    if expected_threads.is_some() && observed == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "No visible thread identities",
        ));
    }
    if expected_threads.is_some_and(|count| count != observed) {
        return Err(invalid_status());
    }
    check_deadline(deadline)?;
    Ok(false)
}

fn status_number(status: &[u8], prefix: &[u8]) -> io::Result<u32> {
    status
        .split(|byte| *byte == b'\n')
        .find_map(|line| line.strip_prefix(prefix))
        .and_then(|field| std::str::from_utf8(field).ok()?.trim().parse().ok())
        .ok_or_else(invalid_status)
}

fn hidden_group_has_writer(
    proc: &Path,
    cgroup: &Path,
    pid: u32,
    deadline: Instant,
    is_writer: &impl Fn(u32) -> bool,
) -> io::Result<bool> {
    let leader = proc.join(pid.to_string());
    let thread_count = || -> io::Result<u32> {
        let status = read_bounded(&leader.join("status"))?;
        if parse_status(&status)?.is_some() || status_number(&status, b"Tgid:")? != pid {
            return Err(invalid_status());
        }
        status_number(&status, b"Threads:")
    };
    let expected = thread_count()?;
    if expected == 1 {
        check_deadline(deadline)?;
        return Ok(false);
    }
    // In the appliance's private cgroup-v2 domain all siblings share one authoritative TID list.
    if read_bounded(&leader.join("cgroup"))? != b"0::/\n"
        || read_bounded(&cgroup.join("cgroup.type"))? != b"domain\n"
    {
        return Err(invalid_status());
    }
    let list = read_bounded(&cgroup.join("cgroup.threads"))?;
    let mut group = HashSet::from([pid]);
    for field in std::str::from_utf8(&list)
        .map_err(|_| invalid_status())?
        .split_ascii_whitespace()
    {
        check_deadline(deadline)?;
        let tid = field.parse::<u32>().map_err(|_| invalid_status())?;
        if tid == 0 || group.contains(&tid) {
            continue;
        }
        let task = proc.join(tid.to_string());
        let status = match read_bounded(&task.join("status")) {
            Err(error) if error.kind() == io::ErrorKind::NotFound && disappeared(&task) => continue,
            result => result?,
        };
        if status_number(&status, b"Tgid:")? == pid {
            if parse_status(&status)?.is_some_and(|uids| uids.into_iter().any(is_writer)) {
                return Ok(true);
            }
            group.insert(tid);
        }
    }
    if group.len() != expected as usize || thread_count()? != expected {
        return Err(invalid_status());
    }
    check_deadline(deadline)?;
    Ok(false)
}

fn check_deadline(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "Process identity scan timed out",
        ));
    }
    Ok(())
}

fn disappeared(path: &Path) -> bool {
    fs::symlink_metadata(path).is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
}

struct TaskIdentity {
    uids: Option<[u32; 4]>,
    threads: u32,
}

fn inspect_live_entry(directory: &Path, deadline: Instant) -> io::Result<Option<TaskIdentity>> {
    let file = directory.join("status");
    for attempt in 0..3 {
        match inspect(&file) {
            Ok(identity) => return Ok(Some(identity)),
            Err(_) if disappeared(directory) => return Ok(None),
            Err(_) if attempt < 2 && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(error) => return Err(error),
        }
    }
    Err(invalid_status())
}

fn inspect(path: &Path) -> io::Result<TaskIdentity> {
    let status = read_bounded(path)?;
    let threads = status_number(&status, b"Threads:")?;
    if threads == 0 {
        return Err(invalid_status());
    }
    Ok(TaskIdentity {
        uids: parse_status(&status)?,
        threads,
    })
}

fn read_bounded(path: &Path) -> io::Result<Vec<u8>> {
    let mut status = Vec::with_capacity(2048);
    File::open(path)?
        .take(MAXIMUM_STATUS + 1)
        .read_to_end(&mut status)?;
    if status.len() as u64 > MAXIMUM_STATUS {
        return Err(invalid_status());
    }
    Ok(status)
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
