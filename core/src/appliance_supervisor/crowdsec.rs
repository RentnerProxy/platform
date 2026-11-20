mod commands;
mod files;
mod online;

use commands::{Helpers, bounded, pause, service, stop};
use files::{desired, status};
use serde_json::json;
use std::{
    fs, io,
    path::Path,
    time::{Duration, Instant},
};
use tokio::{
    process::{Child, Command},
    signal::unix::{SignalKind, signal},
};
use tokio_util::sync::CancellationToken;

const LOCAL_CONFIG: &str = "/usr/share/rentnerproxy/crowdsec/config.yaml";
const ONLINE_CONFIG: &str = "/usr/share/rentnerproxy/crowdsec/config-online.yaml";
const ENGINE: &str = "/usr/local/bin/crowdsec";
const CSCLI: &str = "/usr/local/bin/cscli";
const RETRY: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Stopped,
    Local,
    Online,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EngineState {
    Running,
    Reconcile,
    Failed,
}

struct Supervisor {
    engine: Option<Child>,
    running: Mode,
    community: &'static str,
    console: &'static str,
    attempt: Instant,
    probe: Instant,
    suspended: Instant,
    restarts: u32,
    blocked: bool,
    rotate: bool,
    helpers: Helpers,
}

pub(super) fn protect_capi() -> io::Result<()> {
    files::protect_credential(Path::new(files::CAPI))
}

#[tokio::main(flavor = "current_thread")]
pub(super) async fn serve() -> io::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(io::Error::other("CrowdSec supervisor requires root"));
    }
    let mut term = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let shutdown = CancellationToken::new();
    let notify = shutdown.clone();
    tokio::spawn(async move {
        tokio::select! { _ = term.recv() => (), _ = interrupt.recv() => () }
        notify.cancel();
    });
    let mut supervisor = Supervisor::new(shutdown);
    let result = supervisor.run().await;
    stop(&mut supervisor.engine).await?;
    supervisor.helpers.ensure_reaped()?;
    result
}

impl Supervisor {
    fn new(shutdown: CancellationToken) -> Self {
        let now = Instant::now();
        Self {
            engine: None,
            running: Mode::Stopped,
            community: "disabled",
            console: "not_enrolled",
            attempt: now,
            probe: now,
            suspended: now,
            restarts: 0,
            blocked: false,
            rotate: true,
            helpers: Helpers::new(shutdown),
        }
    }

    fn publish(&self, state: &str) -> io::Result<()> {
        status(
            "status.json",
            json!({"state": state, "restarts": self.restarts, "community": self.community, "console": self.console}),
        )
    }

    async fn run(&mut self) -> io::Result<()> {
        self.publish("stopped")?;
        while !self.helpers.shutdown.is_cancelled() {
            let requested = desired();
            if requested == Mode::Stopped {
                stop(&mut self.engine).await?;
                self.running = Mode::Stopped;
                self.restarts = 0;
                self.blocked = false;
                self.rotate = true;
                self.attempt = Instant::now();
                self.suspended = self.attempt;
                self.community = "disabled";
                self.console = "not_enrolled";
                self.publish("stopped")?;
                pause(1, &self.helpers.shutdown).await;
                continue;
            }
            if self.blocked {
                self.publish("degraded")?;
                pause(1, &self.helpers.shutdown).await;
                continue;
            }
            self.publish("starting")?;
            let started = self.start(requested).await;
            self.helpers.ensure_reaped()?;
            if self.helpers.shutdown.is_cancelled() || desired() != requested {
                stop(&mut self.engine).await?;
                continue;
            }
            if let Err(error) = started {
                if error.kind() == io::ErrorKind::InvalidInput {
                    self.blocked = true;
                    self.publish("degraded")?;
                } else {
                    self.retry().await?;
                }
                continue;
            }
            if self.engine.is_none() {
                continue;
            }
            let readiness = self.ready(requested).await?;
            let ready_since = Instant::now();
            let switched = match readiness {
                EngineState::Running => {
                    self.publish("ready")?;
                    self.monitor().await?
                }
                EngineState::Reconcile => true,
                EngineState::Failed => false,
            };
            stop(&mut self.engine).await?;
            if self.helpers.shutdown.is_cancelled() || desired() == Mode::Stopped || switched {
                continue;
            }
            if self.running == Mode::Online {
                self.suspended = Instant::now() + RETRY;
                self.attempt = self.suspended;
                self.community = "degraded";
                self.console = "degraded";
                self.publish("restarting")?;
                continue;
            }
            if readiness == EngineState::Running && ready_since.elapsed() >= RETRY {
                self.restarts = 0;
            }
            self.retry().await?;
        }
        Ok(())
    }

    async fn retry(&mut self) -> io::Result<()> {
        self.restarts += 1;
        if self.restarts >= 5 {
            self.blocked = true;
            self.publish("degraded")
        } else {
            self.publish("restarting")?;
            pause(1 << (self.restarts - 1), &self.helpers.shutdown).await;
            Ok(())
        }
    }

    async fn start(&mut self, requested: Mode) -> io::Result<()> {
        self.initialize_credentials().await?;
        self.running = Mode::Local;
        let mut config = LOCAL_CONFIG;
        if requested == Mode::Online
            && Instant::now() >= self.suspended
            && fs::symlink_metadata(files::CAPI).is_ok_and(|file| file.is_file())
        {
            if self.protect_online().await.is_ok() && self.validate(ONLINE_CONFIG).await.is_ok() {
                config = ONLINE_CONFIG;
                self.running = Mode::Online;
                self.community = "starting";
                self.probe = Instant::now();
            } else {
                self.community = "degraded";
                self.attempt = Instant::now() + RETRY;
            }
        }
        if config == LOCAL_CONFIG {
            self.validate(config).await?;
        }
        self.helpers.ensure_reaped()?;
        if self.helpers.shutdown.is_cancelled() || desired() != requested {
            return Ok(());
        }
        let mut command = service(ENGINE, &["-c", config]);
        if self.running == Mode::Local {
            command.arg("-no-capi");
        }
        self.engine = Some(command.spawn()?);
        Ok(())
    }

    async fn validate(&self, config: &str) -> io::Result<Vec<u8>> {
        bounded(
            service(ENGINE, &["-t", "-c", config]),
            15,
            false,
            &self.helpers,
        )
        .await
        .map_err(|error| {
            if error.kind() == io::ErrorKind::InvalidData {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Invalid CrowdSec configuration",
                )
            } else {
                error
            }
        })
    }

    async fn cli(
        &self,
        config: &str,
        args: &[&str],
        seconds: u64,
        capture: bool,
    ) -> io::Result<Vec<u8>> {
        let mut command = service(CSCLI, &["-c", config]);
        command.args(args);
        bounded(command, seconds, capture, &self.helpers).await
    }

    async fn initialize_credentials(&mut self) -> io::Result<()> {
        const MACHINE: &str = "rentnerproxy-managed";
        const BOUNCER: &str = "rentnerproxy-caddy";
        let machines = self
            .cli(LOCAL_CONFIG, &["machines", "list", "-o", "json"], 25, true)
            .await?;
        if !files::local_credentials_present()?
            || !online::has_json_field(&machines, "machineId", &json!(MACHINE))
        {
            let _ = self
                .cli(LOCAL_CONFIG, &["machines", "delete", MACHINE], 25, false)
                .await;
            self.cli(
                LOCAL_CONFIG,
                &["machines", "add", MACHINE, "--auto", "--force"],
                25,
                false,
            )
            .await?;
            if !files::local_credentials_present()? {
                return Err(io::Error::other(
                    "CrowdSec local credentials were not created",
                ));
            }
        }
        if self.rotate {
            files::check_previous_key()?;
            let _ = self
                .cli(LOCAL_CONFIG, &["bouncers", "delete", BOUNCER], 25, false)
                .await;
            let key = self
                .cli(
                    LOCAL_CONFIG,
                    &["bouncers", "add", BOUNCER, "-o", "raw"],
                    25,
                    true,
                )
                .await?;
            files::publish_generated_key(key)?;
            self.rotate = false;
        }
        Ok(())
    }

    fn alive(&mut self) -> io::Result<bool> {
        self.engine
            .as_mut()
            .ok_or_else(|| io::Error::other("Missing managed engine"))?
            .try_wait()
            .map(|status| status.is_none())
    }

    fn engine_state(&mut self, requested: Mode, wanted: Mode) -> io::Result<EngineState> {
        if self.helpers.shutdown.is_cancelled()
            || wanted != requested
            || wanted == Mode::Stopped
            || (self.running == Mode::Online && wanted != Mode::Online)
        {
            return Ok(EngineState::Reconcile);
        }
        Ok(if self.alive()? {
            EngineState::Running
        } else {
            EngineState::Failed
        })
    }

    async fn ready(&mut self, requested: Mode) -> io::Result<EngineState> {
        for _ in 0..30 {
            let state = self.engine_state(requested, desired())?;
            if state != EngineState::Running {
                return Ok(state);
            }
            let mut command = Command::new("/usr/bin/curl");
            command.args([
                "--noproxy",
                "*",
                "--fail",
                "--silent",
                "--max-time",
                "1",
                "http://127.0.0.1:18080/health",
            ]);
            let healthy = bounded(command, 1, false, &self.helpers).await.is_ok();
            let state = self.engine_state(requested, desired())?;
            if healthy || state != EngineState::Running {
                return Ok(state);
            }
            pause(1, &self.helpers.shutdown).await;
        }
        Ok(match self.engine_state(requested, desired())? {
            EngineState::Running => EngineState::Failed,
            state => state,
        })
    }

    fn publish_ready_if_current(&mut self, requested: Mode) -> io::Result<bool> {
        if self.engine_state(requested, desired())? != EngineState::Running {
            return Ok(false);
        }
        self.publish("ready")?;
        Ok(true)
    }

    async fn monitor(&mut self) -> io::Result<bool> {
        while !self.helpers.shutdown.is_cancelled() && self.alive()? {
            let requested = desired();
            let publish = match (self.running, requested) {
                (_, Mode::Stopped) => break,
                (Mode::Online, Mode::Local) => {
                    self.attempt = Instant::now();
                    self.suspended = self.attempt;
                    self.community = "disabled";
                    self.console = "not_enrolled";
                    return Ok(true);
                }
                (Mode::Local, Mode::Local) if self.community != "disabled" => {
                    self.community = "disabled";
                    self.console = "not_enrolled";
                    self.attempt = Instant::now();
                    self.suspended = self.attempt;
                    true
                }
                (Mode::Local, Mode::Online) if Instant::now() >= self.attempt => {
                    self.attempt = Instant::now() + RETRY;
                    if self.enable_online().await.is_ok() {
                        if self.engine_state(requested, desired())? != EngineState::Running {
                            continue;
                        }
                        self.community = "starting";
                        return Ok(true);
                    }
                    self.community = "degraded";
                    true
                }
                (Mode::Online, Mode::Online) if Instant::now() >= self.probe => {
                    self.probe_online().await;
                    self.probe = Instant::now() + Duration::from_secs(120);
                    true
                }
                _ => false,
            };
            if publish && !self.publish_ready_if_current(requested)? {
                continue;
            }
            if self.engine_state(requested, desired())? != EngineState::Running {
                continue;
            }
            if let Some(text) = files::take_enrollment()? {
                self.enroll(&text).await?;
                if !self.publish_ready_if_current(requested)? {
                    continue;
                }
            }
            pause(1, &self.helpers.shutdown).await;
        }
        Ok(false)
    }
}

#[cfg(test)]
#[path = "../../tests/private/appliance_supervisor.rs"]
mod tests;
