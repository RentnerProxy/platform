use super::process::{owned_pid, pid, signal_task};
use std::{
    io,
    os::fd::{AsRawFd, OwnedFd},
    time::{Duration, Instant},
};

#[derive(Clone, Copy)]
struct Budget {
    term: Duration,
    forced: Option<Duration>,
}

fn budget(phase: &str) -> io::Result<Budget> {
    let seconds = match phase {
        "web-recovery" | "apps" => 18,
        "controller" | "web" | "application" => 23,
        "crowdsec" => 40,
        _ => return Err(io::Error::other("Invalid supervisor drain phase")),
    };
    Ok(Budget {
        term: Duration::from_secs(seconds),
        forced: (phase == "web-recovery").then_some(Duration::from_secs(2)),
    })
}

pub(super) fn exited(task: &OwnedFd) -> io::Result<bool> {
    let mut descriptor = libc::pollfd {
        fd: task.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let count = unsafe { libc::poll(&mut descriptor, 1, 0) };
    if count < 0 {
        return Err(io::Error::last_os_error());
    }
    if descriptor.revents & (libc::POLLNVAL | libc::POLLERR) != 0 {
        return Err(io::Error::other("Lost pinned child descriptor"));
    }
    Ok(descriptor.revents & (libc::POLLIN | libc::POLLHUP) != 0)
}

fn wait_for_exit(
    targets: &[OwnedFd],
    critical: &[OwnedFd],
    duration: Duration,
) -> io::Result<bool> {
    let deadline = Instant::now() + duration;
    loop {
        let done = targets
            .iter()
            .try_fold(true, |done, task| exited(task).map(|exited| done && exited))?;
        for task in critical {
            if exited(task)? {
                return Err(io::Error::other(
                    "Critical appliance child exited during drain",
                ));
            }
        }
        if done {
            return Ok(true);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(false);
        }
        std::thread::sleep(remaining.min(Duration::from_millis(100)));
    }
}

fn signal_remaining(task: &OwnedFd, signal: i32) -> io::Result<()> {
    match signal_task(task, signal) {
        Err(error) if error.raw_os_error() == Some(libc::ESRCH) => Ok(()),
        other => other,
    }
}

fn drain(targets: &[OwnedFd], critical: &[OwnedFd], budget: Budget) -> io::Result<()> {
    for task in targets {
        if !exited(task)? {
            signal_remaining(task, libc::SIGTERM)?;
        }
    }
    if wait_for_exit(targets, critical, budget.term)? {
        return Ok(());
    }
    for task in targets {
        if !exited(task)? {
            signal_remaining(task, libc::SIGKILL)?;
        }
    }
    if let Some(forced) = budget.forced
        && wait_for_exit(targets, critical, forced)?
    {
        return Ok(());
    }
    Err(io::Error::other(
        "Supervisor drain exceeded its graceful stop budget",
    ))
}

pub(super) fn run(args: &[String]) -> io::Result<()> {
    let (phase, args) = args
        .split_first()
        .ok_or_else(|| io::Error::other("Missing drain phase"))?;
    let budget = budget(phase)?;
    let parent = unsafe { libc::getppid() };
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } != 0
        || unsafe { libc::getppid() } != parent
    {
        return Err(io::Error::other("Supervisor parent disappeared"));
    }
    drain_children(phase, args, parent, budget)
}

fn drain_children(phase: &str, args: &[String], parent: i32, budget: Budget) -> io::Result<()> {
    let (targets, critical) = args.split_at(
        args.iter()
            .position(|arg| arg == "--")
            .ok_or_else(|| io::Error::other("Missing critical child boundary"))?,
    );
    let mut pinned = Vec::new();
    for target in targets {
        let (target, ticks) = match target.split_once(':') {
            Some((target, ticks)) => (
                target,
                Some(ticks.parse::<u64>().map_err(io::Error::other)?),
            ),
            None if phase != "web-recovery" => (target.as_str(), None),
            _ => return Err(io::Error::other("Missing web start time")),
        };
        match owned_pid(pid(target)?, parent, ticks) {
            Ok(task) => pinned.push(task),
            Err(error) if matches!(error.raw_os_error(), Some(libc::ESRCH | libc::ENOENT)) => {}
            Err(error) => return Err(error),
        }
    }
    let critical = critical[1..]
        .iter()
        .map(|value| owned_pid(pid(value)?, parent, None))
        .collect::<io::Result<Vec<_>>>()?;
    drain(&pinned, &critical, budget)
}

#[cfg(test)]
#[path = "../../tests/private/appliance_supervisor_drain.rs"]
mod tests;
