use std::{
    fs, io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    path::Path,
};

fn invalid() -> io::Error {
    io::Error::other("Unproven supervisor process identity")
}

pub(super) fn pid(value: &str) -> io::Result<i32> {
    value
        .parse::<i32>()
        .ok()
        .filter(|pid| *pid > 1)
        .ok_or_else(invalid)
}

fn stat_identity(stat: &[u8]) -> io::Result<(i32, u64)> {
    let (_, fields) = stat.split_at(
        stat.iter()
            .rposition(|byte| *byte == b')')
            .ok_or_else(invalid)?
            + 1,
    );
    let mut fields = std::str::from_utf8(fields)
        .map_err(|_| invalid())?
        .split_ascii_whitespace();
    let parent = fields
        .nth(1)
        .and_then(|field| field.parse().ok())
        .ok_or_else(invalid)?;
    let ticks = fields
        .nth(17)
        .and_then(|field| field.parse().ok())
        .ok_or_else(invalid)?;
    Ok((parent, ticks))
}

pub(super) fn open_pid(pid: i32) -> io::Result<OwnedFd> {
    // pidfd_open pins the original task even if the numeric PID is later recycled.
    let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor as _) })
}

pub(super) fn owned_pid(pid: i32, parent: i32, ticks: Option<u64>) -> io::Result<OwnedFd> {
    let task = open_pid(pid)?;
    let file = Path::new("/proc").join(pid.to_string()).join("stat");
    let (current_parent, start) = stat_identity(&fs::read(file)?)?;
    if current_parent != parent || ticks.is_some_and(|expected| start != expected) {
        return Err(invalid());
    }
    Ok(task)
}

pub(super) fn signal_task(task: &OwnedFd, signal: i32) -> io::Result<()> {
    let status = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            task.as_raw_fd(),
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if status < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/private/appliance_supervisor_process.rs"]
mod tests;
