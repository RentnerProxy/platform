use std::{
    io,
    process::Stdio,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use tokio::{
    io::AsyncReadExt,
    process::{Child, Command},
    time::{sleep, timeout},
};
use tokio_util::sync::CancellationToken;

const OUTPUT_LIMIT: u64 = 1024 * 1024;
const REAP_BUDGET: Duration = Duration::from_secs(2);

pub(super) struct Helpers {
    pub(super) shutdown: CancellationToken,
    failed: AtomicBool,
}

impl Helpers {
    pub(super) fn new(shutdown: CancellationToken) -> Self {
        Self {
            shutdown,
            failed: AtomicBool::new(false),
        }
    }

    pub(super) fn ensure_reaped(&self) -> io::Result<()> {
        if self.failed.load(Ordering::Relaxed) {
            Err(io::Error::other(
                "CrowdSec helper cleanup could not be confirmed",
            ))
        } else {
            Ok(())
        }
    }

    pub(super) fn confirm_cleanup(
        &self,
        signalled: bool,
        reaped: io::Result<()>,
    ) -> io::Result<()> {
        if signalled && reaped.is_ok() {
            return Ok(());
        }

        self.failed.store(true, Ordering::Relaxed);
        self.shutdown.cancel();
        self.ensure_reaped()
    }
}

pub(super) async fn reap_killed(child: &mut Child, budget: Duration) -> io::Result<()> {
    timeout(budget, child.wait()).await.map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "CrowdSec process did not exit after SIGKILL",
        )
    })??;
    Ok(())
}

pub(super) fn service(binary: &str, args: &[&str]) -> Command {
    let mut command = Command::new("/usr/local/bin/gosu");
    command
        .arg("crowdsec")
        .arg(binary)
        .args(args)
        .env_remove("SMTP_USER")
        .env_remove("SMTP_PASSWORD")
        .stdin(Stdio::null())
        .kill_on_drop(true);
    command
}

pub(super) async fn bounded(
    mut command: Command,
    seconds: u64,
    capture: bool,
    helpers: &Helpers,
) -> io::Result<Vec<u8>> {
    if helpers.shutdown.is_cancelled() {
        return Err(io::Error::other("Supervisor stopping"));
    }
    let mut child = command
        .env_remove("SMTP_USER")
        .env_remove("SMTP_PASSWORD")
        .stdin(Stdio::null())
        .stdout(if capture {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .process_group(0)
        .spawn()?;
    let pid = child
        .id()
        .ok_or_else(|| io::Error::other("Missing helper identity"))?;
    let stdout = child.stdout.take();
    let work = async {
        let mut buffer = Vec::new();
        if let Some(pipe) = stdout {
            pipe.take(OUTPUT_LIMIT + 1).read_to_end(&mut buffer).await?;
            if buffer.len() as u64 > OUTPUT_LIMIT {
                return Err(io::Error::other("Command output exceeded limit"));
            }
        }
        let status = child.wait().await?;
        if status.success() {
            Ok(buffer)
        } else if status.code().is_some() {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "CrowdSec helper rejected the operation",
            ))
        } else {
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "CrowdSec helper was interrupted",
            ))
        }
    };
    let result = tokio::select! {
        biased;
        _ = helpers.shutdown.cancelled() => Err(io::Error::other("Supervisor stopping")),
        result = timeout(Duration::from_secs(seconds), work) =>
            result.unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "CrowdSec helper timed out"))),
    };
    if result.is_err() && child.id().is_some() {
        // The group leader is our unreaped child. Its PID cannot have been recycled.
        let sent = unsafe { libc::kill(-(pid as libc::pid_t), libc::SIGKILL) } == 0
            || io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
        helpers.confirm_cleanup(sent, reap_killed(&mut child, REAP_BUDGET).await)?;
    }
    result
}

pub(super) async fn stop(child: &mut Option<Child>) -> io::Result<()> {
    stop_with_grace(child, Duration::from_secs(12)).await
}

pub(super) async fn stop_with_grace(child: &mut Option<Child>, grace: Duration) -> io::Result<()> {
    if let Some(mut child) = child.take()
        && child.try_wait()?.is_none()
    {
        let pid = child
            .id()
            .ok_or_else(|| io::Error::other("Missing engine identity"))?;
        // The supervisor is the sole reaper of this engine child.
        unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
        match timeout(grace, child.wait()).await {
            Ok(result) => {
                result?;
            }
            Err(_) => {
                if let Err(error) = child.start_kill()
                    && error.raw_os_error() != Some(libc::ESRCH)
                {
                    return Err(error);
                }
                reap_killed(&mut child, REAP_BUDGET).await?;
            }
        }
    }
    Ok(())
}

pub(super) async fn pause(seconds: u64, shutdown: &CancellationToken) {
    tokio::select! {
        _ = shutdown.cancelled() => (),
        _ = sleep(Duration::from_secs(seconds)) => (),
    }
}
