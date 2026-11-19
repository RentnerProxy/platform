use super::{Command, Manager, Value, bad, control, io, json};
use std::{future::Future, time::Duration};
use tokio::net::UnixStream;

impl Manager {
    pub(super) fn status(&self) -> Value {
        let mut status = serde_json::Map::new();
        for (id, s) in self.journal.slots() {
            status.insert(id.clone(), json!({
                "appId": s.app_id, "uid": s.uid, "generation": s.generation,
                "active": s.active.as_ref().map(|p| &p.version),
                "candidate": s.candidate.as_ref().map(|p| &p.version),
                "previous": s.previous.as_ref().map(|p| &p.version),
                "running": self.running.contains_key(id), "recoveryRequired": s.recovery_required,
                "desiredRunning": s.desired_running, "removal": s.removal,
            }));
        }
        Value::Object(status)
    }

    pub(super) async fn stop(&mut self, id: &str) -> io::Result<()> {
        let mut slot = self.journal.slot(id)?.clone();
        if slot.removal != super::Removal::Installed {
            return Err(bad("Installation is reserved for removal or purge"));
        }
        slot.desired_running = false;
        self.journal.save(id, slot)?;
        self.drain_slots(vec![id.to_owned()]).await
    }

    async fn handle_during(&mut self, busy: &str, mut stream: UnixStream) -> io::Result<()> {
        let result = match control::read(&mut stream).await {
            Ok(Command::Status) => Ok(self.status()),
            Ok(Command::Stop { installation_id }) if installation_id != busy => {
                self.stop(&installation_id).await.map(|()| Value::Null)
            }
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "Application lifecycle operation in progress. Retry when it completes.",
            )),
            Err(error) => Err(error),
        };
        Self::respond(&mut stream, result).await
    }

    // External operations may wait for downloads, provisioning or app readiness. The
    // manager retains sole ownership of journal writes and the in-flight installation.
    pub(super) async fn during<T>(
        &mut self,
        busy: &str,
        phase: impl Future<Output = io::Result<T>>,
    ) -> io::Result<T> {
        let Some(listener) = self.listener.clone() else {
            return phase.await;
        };
        let mut tick = tokio::time::interval_at(
            tokio::time::Instant::now() + Duration::from_secs(2),
            Duration::from_secs(2),
        );
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tokio::pin!(phase);
        let mut accepting = true;
        loop {
            let connection = tokio::select! {
                biased;
                result = &mut phase => return result,
                _ = tick.tick() => None,
                connection = listener.accept(), if accepting => match connection {
                    Ok((stream, _)) => Some(stream),
                    Err(error) => {
                        eprintln!("Application control accept failed: {error}");
                        accepting = false;
                        continue;
                    }
                },
            };
            let servicing = async {
                let side = match connection {
                    Some(stream) => self.handle_during(busy, stream).await,
                    None => self.check_other_exits(Some(busy)).await,
                };
                if let Err(error) = side {
                    eprintln!("Unrelated application control or retirement failed: {error}");
                }
                self.journal.writable()
            };
            tokio::pin!(servicing);
            // Finish an accepted stop even when the primary phase completes first. Its
            // drain has a 16 s budget, and socket reads/writes are bounded to 2 s each.
            tokio::select! {
                result = &mut phase => { servicing.await?; return result; },
                result = &mut servicing => result?,
            }
        }
    }
}
