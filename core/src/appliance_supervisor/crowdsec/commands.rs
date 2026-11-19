use std::{io, process::Stdio, time::Duration};
use tokio::{
    io::AsyncReadExt,
    process::{Child, Command},
    time::{sleep, timeout},
};
use tokio_util::sync::CancellationToken;

const OUTPUT_LIMIT: u64 = 1024 * 1024;

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
    shutdown: &CancellationToken,
) -> io::Result<Vec<u8>> {
    if shutdown.is_cancelled() {
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
        if child.wait().await?.success() {
            Ok(buffer)
        } else {
            Err(io::Error::other("CrowdSec helper failed"))
        }
    };
    let result = tokio::select! {
        biased;
        _ = shutdown.cancelled() => Err(io::Error::other("Supervisor stopping")),
        result = timeout(Duration::from_secs(seconds), work) =>
            result.unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "CrowdSec helper timed out"))),
    };
    if result.is_err() && child.id().is_some() {
        // The group leader is our unreaped child. Its PID cannot have been recycled.
        unsafe { libc::kill(-(pid as libc::pid_t), libc::SIGKILL) };
        child.wait().await?;
    }
    result
}

pub(super) async fn stop(child: &mut Option<Child>) -> io::Result<()> {
    if let Some(mut child) = child.take()
        && child.try_wait()?.is_none()
    {
        let pid = child
            .id()
            .ok_or_else(|| io::Error::other("Missing engine identity"))?;
        // The supervisor is the sole reaper of this engine child.
        unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
        match timeout(Duration::from_secs(12), child.wait()).await {
            Ok(result) => {
                result?;
            }
            Err(_) => child.kill().await?,
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
