use super::Error;
use std::collections::HashMap;
use tokio::{sync::Semaphore, time::Instant};

// Admission sizes for app upstream probes. One installation must sustain 1,000
// policies at a 60 s interval (about 17 probes per second), the same shape as
// built-in monitoring, so the token bucket refills at 20 probes per second
// (1,200 per minute) and absorbs a 6 s burst of 120 probes.
pub(super) const APP_GLOBAL_PERMITS: usize = 128;
pub(super) const APP_INSTALLATION_IN_FLIGHT: usize = 64;
pub(super) const APP_BUCKET_CAPACITY: f64 = 120.0;
pub(super) const APP_REFILL_PER_SECOND: f64 = 20.0;
// Hard cap on tracked installations. Entries are pruned once idle and fully
// refilled; reaching the cap with all entries still busy or draining returns
// Busy instead of growing the map.
pub(super) const APP_TRACKED_INSTALLATIONS: usize = 1024;

struct Installation {
    in_flight: usize,
    tokens: f64,
    refilled_at: Instant,
}
impl Installation {
    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.refilled_at);
        self.tokens =
            (self.tokens + elapsed.as_secs_f64() * APP_REFILL_PER_SECOND).min(APP_BUCKET_CAPACITY);
        self.refilled_at = now;
    }
    fn is_idle_and_full(&self, now: Instant) -> bool {
        let mut copy = Installation {
            in_flight: self.in_flight,
            tokens: self.tokens,
            refilled_at: self.refilled_at,
        };
        copy.refill(now);
        copy.in_flight == 0 && copy.tokens >= APP_BUCKET_CAPACITY
    }
}

pub(in crate::runtime) struct AppAdmission {
    global: Semaphore,
    installations: std::sync::Mutex<HashMap<String, Installation>>,
}
impl Default for AppAdmission {
    fn default() -> Self {
        Self {
            global: Semaphore::new(APP_GLOBAL_PERMITS),
            installations: std::sync::Mutex::default(),
        }
    }
}
pub(super) struct AppPermit<'a> {
    admission: &'a AppAdmission,
    installation: String,
    _global: tokio::sync::SemaphorePermit<'a>,
}
impl AppAdmission {
    /// Concurrency first (global permit, then the installation slot), then one
    /// token. Busy never consumes a token; an empty bucket is RateLimited.
    pub(super) fn acquire(&self, installation: &str) -> std::result::Result<AppPermit<'_>, Error> {
        let global = self.global.try_acquire().map_err(|_| Error::Busy)?;
        let mut installations = self
            .installations
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        // Sampled under the lock, so no refill moves an installation's refill time backwards.
        let now = Instant::now();
        if !installations.contains_key(installation) {
            if installations.len() >= APP_TRACKED_INSTALLATIONS {
                installations.retain(|_, entry| !entry.is_idle_and_full(now));
                if installations.len() >= APP_TRACKED_INSTALLATIONS {
                    return Err(Error::Busy);
                }
            }
            installations.insert(
                installation.to_owned(),
                Installation {
                    in_flight: 0,
                    tokens: APP_BUCKET_CAPACITY,
                    refilled_at: now,
                },
            );
        }
        let entry = installations
            .get_mut(installation)
            .ok_or(Error::Unavailable)?;
        entry.refill(now);
        if entry.in_flight >= APP_INSTALLATION_IN_FLIGHT {
            return Err(Error::Busy);
        }
        if entry.tokens < 1.0 {
            return Err(Error::RateLimited);
        }
        entry.tokens -= 1.0;
        entry.in_flight += 1;
        drop(installations);
        Ok(AppPermit {
            admission: self,
            installation: installation.to_owned(),
            _global: global,
        })
    }
    #[cfg(test)]
    pub(super) fn available_global(&self) -> usize {
        self.global.available_permits()
    }
    #[cfg(test)]
    pub(super) fn tracked(&self) -> usize {
        self.installations
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .len()
    }
}
impl Drop for AppPermit<'_> {
    fn drop(&mut self) {
        let mut installations = self
            .admission
            .installations
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(entry) = installations.get_mut(&self.installation) {
            entry.in_flight = entry.in_flight.saturating_sub(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn id(index: usize) -> String {
        format!("0198d98a-0000-7000-8000-{index:012}")
    }

    #[tokio::test(start_paused = true)]
    async fn per_installation_cap_is_busy_without_consuming_a_token_or_blocking_others() {
        let admission = AppAdmission::default();
        let held: Vec<_> = (0..APP_INSTALLATION_IN_FLIGHT)
            .map(|_| admission.acquire(&id(1)).unwrap())
            .collect();
        assert!(matches!(admission.acquire(&id(1)), Err(Error::Busy)));
        assert!(admission.acquire(&id(2)).is_ok());
        assert_eq!(
            admission.available_global(),
            APP_GLOBAL_PERMITS - APP_INSTALLATION_IN_FLIGHT
        );
        drop(held);
        assert_eq!(admission.available_global(), APP_GLOBAL_PERMITS);
        // 64 tokens were spent; the rejected attempt did not take another one.
        let tokens = admission.installations.lock().unwrap()[&id(1)].tokens;
        assert!((tokens - (APP_BUCKET_CAPACITY - 64.0)).abs() < 1e-9);
    }

    #[tokio::test(start_paused = true)]
    async fn global_cap_is_busy() {
        let admission = AppAdmission::default();
        let held: Vec<_> = (0..APP_GLOBAL_PERMITS)
            .map(|index| {
                admission
                    .acquire(&id(index / APP_INSTALLATION_IN_FLIGHT))
                    .unwrap()
            })
            .collect();
        assert!(matches!(admission.acquire(&id(9)), Err(Error::Busy)));
        drop(held);
        assert!(admission.acquire(&id(9)).is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn token_bucket_rate_limits_after_the_burst_and_refills_over_time() {
        let admission = AppAdmission::default();
        for _ in 0..APP_BUCKET_CAPACITY as usize {
            drop(admission.acquire(&id(1)).unwrap());
        }
        assert!(matches!(admission.acquire(&id(1)), Err(Error::RateLimited)));
        // Slots are released when rate limited.
        assert_eq!(admission.available_global(), APP_GLOBAL_PERMITS);
        assert_eq!(admission.installations.lock().unwrap()[&id(1)].in_flight, 0);
        assert!(admission.acquire(&id(2)).is_ok());
        tokio::time::advance(Duration::from_millis(49)).await;
        assert!(matches!(admission.acquire(&id(1)), Err(Error::RateLimited)));
        tokio::time::advance(Duration::from_millis(1)).await;
        drop(admission.acquire(&id(1)).unwrap());
        assert!(matches!(admission.acquire(&id(1)), Err(Error::RateLimited)));
        tokio::time::advance(Duration::from_secs(1)).await;
        let burst: Vec<_> = (0..20)
            .map(|_| admission.acquire(&id(1)).unwrap())
            .collect();
        assert!(matches!(admission.acquire(&id(1)), Err(Error::RateLimited)));
        drop(burst);
    }

    #[tokio::test(start_paused = true)]
    async fn idle_full_entries_are_pruned_and_the_tracked_set_is_bounded() {
        let admission = AppAdmission::default();
        for index in 0..APP_TRACKED_INSTALLATIONS {
            drop(admission.acquire(&id(index)).unwrap());
        }
        assert_eq!(admission.tracked(), APP_TRACKED_INSTALLATIONS);
        assert!(matches!(
            admission.acquire(&id(APP_TRACKED_INSTALLATIONS)),
            Err(Error::Busy)
        ));
        assert_eq!(admission.tracked(), APP_TRACKED_INSTALLATIONS);
        // Idle but not yet refilled: still tracked.
        assert!(matches!(
            admission.acquire(&id(APP_TRACKED_INSTALLATIONS)),
            Err(Error::Busy)
        ));
        tokio::time::advance(Duration::from_millis(50)).await;
        let _admitted = admission.acquire(&id(APP_TRACKED_INSTALLATIONS)).unwrap();
        assert_eq!(admission.tracked(), 1);
    }
}
