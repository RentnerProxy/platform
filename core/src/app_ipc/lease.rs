use std::{
    io,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use tokio::time::{Instant, sleep_until, timeout, timeout_at};

use super::gateway::Generation;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
const POLL_INTERVAL: Duration = Duration::from_secs(5);
const MIN_POLL_INTERVAL: Duration = Duration::from_millis(200);
const FINAL_POLL_LEAD: Duration = Duration::from_millis(80);

pub(super) async fn check(generation: &Generation) -> io::Result<Option<Instant>> {
    let Some(expires_at) = timeout(REQUEST_TIMEOUT, generation.lease_expires_at()).await?? else {
        return Ok(None);
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?;
    let remaining = Duration::from_millis(expires_at).saturating_sub(now);
    if remaining.is_zero() {
        return Ok(None);
    }
    Instant::now()
        .checked_add(remaining)
        .map(Some)
        .ok_or_else(|| io::Error::other("Invalid app lease expiry"))
}

pub(super) async fn maintain(generation: &Generation, mut deadline: Instant) {
    loop {
        let now = Instant::now();
        let remaining = deadline.saturating_duration_since(now);
        if remaining <= FINAL_POLL_LEAD {
            sleep_until(deadline).await;
            return;
        }
        let interval = (remaining / 2).clamp(MIN_POLL_INTERVAL, POLL_INTERVAL);
        // Keep one bounded probe ahead of short leases even when the normal
        // minimum poll interval would reach or pass the verified deadline.
        sleep_until((now + interval).min(deadline - FINAL_POLL_LEAD)).await;
        if Instant::now() >= deadline {
            return;
        }
        let observed = timeout_at(deadline, check(generation)).await;
        if Instant::now() >= deadline {
            return;
        }
        match observed {
            Ok(Ok(Some(renewed))) => deadline = renewed,
            Ok(Err(_)) => {} // A transient failure never extends the last verified deadline.
            Ok(Ok(None)) | Err(_) => return,
        }
    }
}
