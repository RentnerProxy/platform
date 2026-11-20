use super::{Command, DRAIN_IO_BUDGET, Manager, Value, bad, control, io, json, valid_id};
use std::{future::Future, time::Duration};
use tokio::{net::UnixStream, task::Id, time::Instant};

pub(super) enum Operation<'a> {
    Stage(&'a str),
    Launch(&'a str),
}

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
        self.begin_stop(id)?;
        self.wait_for_drain(id).await
    }

    fn begin_stop(&mut self, id: &str) -> io::Result<Id> {
        if !valid_id(id) {
            return Err(bad("Invalid installation ID"));
        }
        let mut slot = self.journal.slot(id)?.clone();
        if slot.removal != super::Removal::Installed {
            return Err(bad("Installation is reserved for removal or purge"));
        }
        slot.desired_running = false;
        self.journal.save(id, slot)?;
        if let Some(task) = self.drain_task(id) {
            Ok(task)
        } else {
            self.begin_drain(id.to_owned(), Instant::now() + DRAIN_IO_BUDGET)
        }
    }

    fn has_pending_stops(&self) -> bool {
        self.draining
            .values()
            .any(|drain| drain.stop_reply.is_some())
    }

    pub(super) fn admit_request(
        &self,
        request: Command,
        busy: Option<&str>,
        accepting_stops: bool,
    ) -> io::Result<Command> {
        match &request {
            Command::Status => (),
            Command::Stop { installation_id } => {
                if !accepting_stops
                    || Some(installation_id.as_str()) == busy
                    || self
                        .drain_task(installation_id)
                        .is_some_and(|task| self.draining[&task].stop_reply.is_some())
                {
                    return Err(lifecycle_busy());
                }
            }
            _ if busy.is_some() || self.has_pending_stops() => return Err(lifecycle_busy()),
            _ => (),
        }
        Ok(request)
    }

    pub(super) async fn defer_stop(
        &mut self,
        id: String,
        mut stream: UnixStream,
    ) -> io::Result<()> {
        match self.begin_stop(&id) {
            Ok(task) => {
                // Admission allows one stop reply per slot, and drain jobs never
                // mutate this table. Keep servicing control while the job runs.
                self.draining
                    .get_mut(&task)
                    .expect("tracked drain task")
                    .stop_reply = Some(stream);
                Ok(())
            }
            Err(error) => Self::respond(&mut stream, Err(error)).await,
        }
    }

    async fn handle_during(
        &mut self,
        request: io::Result<Command>,
        mut stream: UnixStream,
    ) -> io::Result<()> {
        let result = match request {
            Ok(Command::Status) => Ok(self.status()),
            Ok(Command::Stop { installation_id }) => {
                return self.defer_stop(installation_id, stream).await;
            }
            Ok(_) => Err(lifecycle_busy()),
            Err(error) => Err(error),
        };
        Self::respond(&mut stream, result).await
    }

    // External operations may wait for downloads, provisioning or app readiness. The
    // manager retains sole ownership of journal writes and the in-flight installation.
    pub(super) async fn during<T>(
        &mut self,
        operation: Operation<'_>,
        phase: impl Future<Output = io::Result<T>>,
    ) -> io::Result<T> {
        let Some(listener) = self.listener.clone() else {
            return phase.await;
        };
        // Both commands reserve the installation. Staging only downloads a candidate,
        // so its existing generation can still be retired while the download runs.
        let (busy, exclude_from_retirement) = match operation {
            Operation::Stage(id) => (id, None),
            Operation::Launch(id) => (id, Some(id)),
        };
        let mut tick = tokio::time::interval_at(
            Instant::now() + Duration::from_secs(2),
            Duration::from_secs(2),
        );
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tokio::pin!(phase);
        let mut accepting = true;
        let mut completed = None;
        loop {
            // A following phase may spend time outside the listener. Finish every
            // accepted explicit Stop before handing back control. Implicit drains
            // keep running independently of the primary phase.
            if !self.has_pending_stops()
                && let Some(result) = completed.take()
            {
                return result;
            }
            let mut stream = tokio::select! {
                biased;
                result = &mut phase, if completed.is_none() => {
                    completed = Some(result);
                    continue;
                }
                _ = tick.tick() => {
                    if let Err(error) = self.check_exits(exclude_from_retirement) {
                        eprintln!("Application exit check failed: {error}");
                    }
                    self.journal.writable()?;
                    continue;
                }
                Some(job) = self.drains.join_next_with_id(), if !self.drains.is_empty() => {
                    self.report_exit(job).await?;
                    continue;
                }
                connection = listener.accept(), if accepting => match connection {
                    Ok((stream, _)) => stream,
                    Err(error) => {
                        eprintln!("Application control accept failed: {error}");
                        accepting = false;
                        continue;
                    }
                },
            };
            let request = {
                let read = control::read(&mut stream);
                tokio::pin!(read);
                // Finish the bounded frame read even when the phase completes
                // first, then use the new admission state for this request.
                tokio::select! {
                    biased;
                    result = &mut phase, if completed.is_none() => {
                        completed = Some(result);
                        read.await
                    }
                    request = &mut read => request,
                }
            };
            let request = request
                .and_then(|request| self.admit_request(request, Some(busy), completed.is_none()));
            if let Err(error) = self.handle_during(request, stream).await {
                eprintln!("Application control failed during lifecycle: {error}");
            }
            self.journal.writable()?;
        }
    }
}

fn lifecycle_busy() -> io::Error {
    io::Error::new(
        io::ErrorKind::WouldBlock,
        "Application lifecycle operation in progress. Retry when it completes.",
    )
}
