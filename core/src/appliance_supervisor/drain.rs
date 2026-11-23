use super::process::{owned_pid, pid, signal_task};
use std::{
    fs, io,
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

fn require_critical_children(critical: &[OwnedFd]) -> io::Result<()> {
    for task in critical {
        if exited(task)? {
            return Err(io::Error::other(
                "Critical appliance child exited during drain",
            ));
        }
    }
    Ok(())
}

fn wait_for_app_shutdown_handler(
    pid: i32,
    task: &OwnedFd,
    critical: &[OwnedFd],
    deadline: Instant,
) -> io::Result<()> {
    const SIGTERM_MASK: u64 = 1 << (libc::SIGTERM - 1);
    let path = format!("/proc/{pid}/status");
    loop {
        require_critical_children(critical)?;
        if exited(task)? {
            return Ok(());
        }
        let status = match fs::read_to_string(&path) {
            Ok(status) => status,
            Err(error) if error.kind() == io::ErrorKind::NotFound && exited(task)? => return Ok(()),
            Err(error) => return Err(error),
        };
        let caught = status
            .lines()
            .find_map(|line| line.strip_prefix("SigCgt:"))
            .and_then(|mask| u64::from_str_radix(mask.trim(), 16).ok())
            .ok_or_else(|| io::Error::other("Could not read app manager signal handlers"))?;
        if caught & SIGTERM_MASK != 0 {
            return Ok(());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::other(
                "App manager shutdown handler did not become ready",
            ));
        }
        std::thread::sleep(remaining.min(Duration::from_millis(25)));
    }
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
        require_critical_children(critical)?;
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
    let critical = critical[1..]
        .iter()
        .map(|value| owned_pid(pid(value)?, parent, None))
        .collect::<io::Result<Vec<_>>>()?;
    let deadline = Instant::now() + budget.term;
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
        let target = pid(target)?;
        match owned_pid(target, parent, ticks) {
            Ok(task) => {
                // Catch-up maintenance can arrive while the app manager is still starting.
                if phase == "apps" {
                    wait_for_app_shutdown_handler(target, &task, &critical, deadline)?;
                }
                pinned.push(task);
            }
            Err(error) if matches!(error.raw_os_error(), Some(libc::ESRCH | libc::ENOENT)) => {}
            Err(error) => return Err(error),
        }
    }
    let budget = if phase == "apps" {
        Budget {
            term: deadline.saturating_duration_since(Instant::now()),
            ..budget
        }
    } else {
        budget
    };
    drain(&pinned, &critical, budget)
}

#[cfg(test)]
#[path = "../../tests/private/appliance_supervisor_drain.rs"]
mod tests;
