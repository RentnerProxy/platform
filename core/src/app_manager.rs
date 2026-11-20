mod control;
mod gateway;
mod journal;
mod removal;
mod runtime;
mod service;
mod storage;
#[cfg(test)]
#[path = "../tests/private/app_manager.rs"]
mod tests;

use crate::app_install::{Installer, StagedPackage};
use crate::appliance_process::{uid_in_use, verify_uid_stopped};
use control::Command;
pub use control::run_app_control;
use gateway::{Gateway, identity, lease};
use journal::{Data, Grant, Journal, Release, Removal, Slot};
use runtime::Running;
use serde_json::{Value, json};
use service::Operation;
use std::{
    collections::BTreeMap,
    fs::File,
    io,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::AsyncWriteExt,
    task::JoinSet,
    time::{sleep, timeout},
};

const MAX_GENERATION: u64 = 9_007_199_254_740_991;
// The supervisor permits 18 s for the manager. Reserve time for journal writes and exit.
const DRAIN_IO_BUDGET: Duration = Duration::from_secs(16);
const SHUTDOWN_BUDGET: Duration = Duration::from_secs(17);
fn bad(message: &'static str) -> io::Error {
    io::Error::other(message)
}
fn valid_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(*c, b'-' | b'_'))
}

struct Manager {
    listener: Option<Arc<tokio::net::UnixListener>>,
    config: PathBuf,
    journal: Journal,
    gateway: Gateway,
    running: BTreeMap<String, Running>,
    fence_cursor: String,
}

impl Manager {
    async fn package(
        config: PathBuf,
        app: String,
        version: String,
        record: Option<Release>,
    ) -> io::Result<StagedPackage> {
        let (send, result) = tokio::sync::oneshot::channel();
        // Catalog downloads may outlive a shutdown request. Only the async owner publishes journal transitions.
        std::thread::Builder::new()
            .name("app-package".into())
            .spawn(move || {
                let _ = send.send((|| {
                    let installer = Installer::open(&config)?;
                    let package = if let Some(record) = record {
                        recover(&installer, &app, &record)?
                    } else {
                        installer.stage(&app, &version)?
                    };
                    if package.manifest["id"] != app
                        || package.manifest["version"] != version
                        || package.manifest["entrypoint"] != "bin/app"
                    {
                        return Err(bad("Signed application identity mismatch"));
                    }
                    Ok(package)
                })());
            })?;
        result.await.map_err(io::Error::other)?
    }

    async fn allocate(&self, app_id: String) -> io::Result<Slot> {
        if self.journal.slots().len() >= journal::LIMIT {
            return Err(bad("Installation capacity exceeded"));
        }
        for uid in 20000..=59999 {
            if self.journal.slots().values().any(|s| s.uid == uid) || !runtime::uid_available(uid)?
            {
                continue;
            }
            if uid_in_use(uid)? || !runtime::database_uid_vacant(uid).await? {
                continue;
            }
            return Ok(Slot {
                uid,
                app_id,
                authority_recorded: Some(false),
                storage_claimed: Some(false),
                ..Default::default()
            });
        }
        Err(bad("No unused installation UID"))
    }

    async fn stage(
        &mut self,
        id: &str,
        app: String,
        version: String,
        download: impl Future<Output = io::Result<StagedPackage>>,
    ) -> io::Result<()> {
        if app.len() > 98 || version.len() > 128 {
            return Err(bad("Invalid package selector"));
        }
        if self
            .journal
            .slots()
            .get(id)
            .is_some_and(|s| s.app_id != app)
        {
            return Err(bad("Installation belongs to another app"));
        }
        let package = self.during(Operation::Stage(id), download).await?;
        let mut slot = match self.journal.slots().get(id) {
            Some(s) => s.clone(),
            None => self.allocate(app).await?,
        };
        slot.candidate = Some(Release {
            version,
            archive_sha256: package.archive_sha256,
            manifest_sha256: package.manifest_sha256,
            catalog_revision: package.catalog_revision,
        });
        self.journal.save(id, slot)
    }

    async fn writer(&self, uid: u32) -> io::Result<File> {
        Self::wait_writer(self.journal.writer_path(uid), uid).await
    }

    async fn wait_writer(path: PathBuf, uid: u32) -> io::Result<File> {
        timeout(Duration::from_secs(11), async {
            loop {
                match journal::lock(&path) {
                    Ok(file) => loop {
                        match tokio::task::spawn_blocking(move || verify_uid_stopped(uid)).await? {
                            Ok(()) => return Ok(file),
                            // Concurrent thread creation can invalidate a /proc snapshot.
                            // Hold the writer and require a fresh, conclusive scan.
                            Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                                sleep(Duration::from_millis(100)).await
                            }
                            Err(e) => return Err(e),
                        }
                    },
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        sleep(Duration::from_millis(100)).await
                    }
                    Err(e) => return Err(e),
                }
            }
        })
        .await?
    }

    async fn fence(&mut self, id: &str) -> io::Result<File> {
        let mut slot = self.journal.slot(id)?.clone();
        if let Some(mut live) = self.running.remove(id) {
            live.close();
            live.stop().await?;
        }
        let writer = self.writer(slot.uid).await?;
        if slot.pending_fence {
            Self::retire(&self.gateway, id, &slot).await?;
            slot.pending_fence = false;
            slot.authority_recorded = Some(true);
            self.journal.save(id, slot)?;
        }
        Ok(writer)
    }

    async fn retire(gateway: &Gateway, id: &str, slot: &Slot) -> io::Result<()> {
        let (authority, database) = tokio::join!(
            Self::retire_authority(gateway, id, slot),
            Self::retire_database(slot)
        );
        database?;
        authority
    }

    async fn retire_database(slot: &Slot) -> io::Result<()> {
        if slot.database_provisioned {
            runtime::fence_database(slot.uid).await?;
        }
        Ok(())
    }

    async fn retire_authority(gateway: &Gateway, id: &str, slot: &Slot) -> io::Result<()> {
        let body = json!({"identity":identity(id,slot)});
        gateway.post("retire", body.clone()).await?;
        timeout(Duration::from_secs(6), async {
            loop {
                match gateway.post("workers-stopped", body.clone()).await {
                    Err(e) if e.kind() == io::ErrorKind::ResourceBusy => {
                        sleep(Duration::from_millis(200)).await
                    }
                    result => return result,
                }
            }
        })
        .await?
    }

    async fn launch(
        &mut self,
        id: &str,
        release: Release,
        grants: Option<&[Grant]>,
        mut boot_lock_retries: Option<&mut usize>,
    ) -> io::Result<()> {
        let slot = self.journal.slot(id)?.clone();
        let config = self.config.clone();
        let package = self
            .during(Operation::Launch(id), async {
                loop {
                    let result = Self::package(
                        config.clone(),
                        slot.app_id.clone(),
                        release.version.clone(),
                        Some(release.clone()),
                    )
                    .await;
                    if result
                        .as_ref()
                        .is_err_and(|e| e.kind() == io::ErrorKind::WouldBlock)
                        && let Some(remaining) = boot_lock_retries.as_deref_mut()
                        && *remaining > 0
                    {
                        *remaining -= 1;
                        sleep(Duration::from_millis(200)).await;
                        continue;
                    }
                    return result;
                }
            })
            .await?;
        let data = package.manifest.get("data").map(read_data).transpose()?;
        if !slot.accepts(&release, data.as_ref()) {
            return Err(bad("Declared data versions require migration or recovery"));
        }
        let generation = slot
            .generation
            .checked_add(1)
            .filter(|n| *n <= MAX_GENERATION)
            .ok_or_else(|| bad("Generation limit reached"))?;
        let writer = self.fence(id).await?;
        let mut slot = self.journal.slot(id)?.clone();
        slot.generation = generation;
        slot.require_recovery();
        slot.pending_fence = true;
        self.journal.save(id, slot.clone())?;
        let who = identity(id, &slot);
        let (mut registration, deadline) = lease(&who)?;
        registration["capabilities"] = package.manifest["capabilities"].clone();
        registration["permissionKeys"] = package.manifest["permissions"].clone();
        registration["hasUi"] = package.manifest.get("ui").is_some().into();
        self.gateway.post("register", registration).await?;
        let renewal = runtime::Renewal::start(self.gateway.clone(), who.clone(), deadline);
        slot.authority_recorded = Some(true);
        self.journal.save(id, slot.clone())?;
        if let Some(grants) = grants {
            self.gateway
                .post("grants", json!({"identity":who,"grants":grants}))
                .await?;
        }
        // A crash between filesystem publication and its acknowledgement is ambiguous.
        // Legacy/unknown evidence keeps backup's conservative positive-generation checks.
        if slot.storage_claimed == Some(false) {
            slot.storage_claimed = None;
            self.journal.save(id, slot.clone())?;
        }
        storage::claim(id, &slot)?;
        if slot.storage_claimed != Some(true) {
            slot.storage_claimed = Some(true);
            self.journal.save(id, slot.clone())?;
        }
        if data.is_some()
            && !slot.database_provisioned
            && !runtime::database_uid_vacant(slot.uid).await?
        {
            return Err(bad("Database identity is already occupied"));
        }
        slot.database_provisioned |= data.is_some();
        self.journal.save(id, slot.clone())?;
        self.during(
            Operation::Launch(id),
            runtime::provision(slot.uid, data.is_some(), &writer),
        )
        .await?;
        slot.written = data;
        slot.provider_dependencies_unknown |= package.manifest["providers"]
            .as_array()
            .is_none_or(|providers| !providers.is_empty());
        self.journal.save(id, slot.clone())?;
        let mut live = self
            .during(
                Operation::Launch(id),
                Running::launch(id, &slot, &package, &writer, renewal),
            )
            .await?;
        if live.exited()? {
            return Err(bad("App or lease expired before activation"));
        }
        if grants.is_some() {
            // Only activation can publish staged grants. Persist uncertainty before sending it.
            slot.grants_uncertain = Some(true);
            self.journal.save(id, slot.clone())?;
        }
        live.activate(&self.gateway, &who).await?;
        if live.exited()? {
            return Err(bad("App exited during activation"));
        }
        slot.commit_release(release);
        slot.desired_running = true;
        slot.recovery_required = false;
        slot.grants_uncertain = None;
        self.journal.save(id, slot)?;
        self.running.insert(id.to_owned(), live);
        Ok(())
    }

    async fn switch(
        &mut self,
        id: &str,
        target: Release,
        grants: Option<&[Grant]>,
    ) -> io::Result<()> {
        let before = self.journal.slot(id)?.clone();
        match self.launch(id, target, grants, None).await {
            Ok(()) => Ok(()),
            Err(error) => {
                let after = self.journal.slot(id)?;
                if self.running.contains_key(id)
                    || after.generation == before.generation && !after.pending_fence
                {
                    return Err(error);
                }
                self.fence(id).await?;
                if before.desired_running
                    && let Some(active) = before.active
                {
                    // The failed activation may have committed new grants. Replaying an old
                    // grant set could also restore access an operator revoked during cutover.
                    let uncertain = self.journal.slot(id)?.uncertain_grants();
                    if self
                        .launch(id, active, uncertain.then_some([].as_slice()), None)
                        .await
                        .is_ok()
                    {
                        let grants = if uncertain {
                            "grants cleared. Reapprove the required grants"
                        } else {
                            "previously approved grants"
                        };
                        return Err(io::Error::new(
                            error.kind(),
                            format!("{error}. Previous release restarted with {grants}."),
                        ));
                    }
                    self.fence(id).await?;
                }
                Err(error)
            }
        }
    }

    async fn execute(&mut self, cmd: Command) -> io::Result<Value> {
        if cmd.id().is_some_and(|id| !valid_id(id)) {
            return Err(bad("Invalid installation ID"));
        }
        if let Some(id) = cmd.id()
            && let Some(slot) = self.journal.slots().get(id)
            && slot.removal != Removal::Installed
            && !matches!(cmd, Command::Remove { .. } | Command::Purge { .. })
        {
            if matches!(cmd, Command::Start { .. })
                && slot.removal == Removal::Removing
                && slot.active.is_some()
            {
                self.fence(id).await?;
                let mut slot = self.journal.slot(id)?.clone();
                slot.removal = Removal::Installed;
                self.journal.save(id, slot)?;
            } else {
                return Err(bad("Installation is reserved for removal or purge"));
            }
        }
        match cmd {
            Command::Status => return Ok(self.status()),
            Command::Stage {
                installation_id,
                app_id,
                version,
            } => {
                let download =
                    Self::package(self.config.clone(), app_id.clone(), version.clone(), None);
                self.stage(&installation_id, app_id, version, download)
                    .await?;
            }
            Command::Remove { installation_id } => self.remove(&installation_id).await?,
            Command::Discard {
                installation_id,
                release,
            } => {
                let mut slot = self.journal.slot(&installation_id)?.clone();
                let retained = match release {
                    control::InactiveRelease::Candidate => &mut slot.candidate,
                    control::InactiveRelease::Previous => &mut slot.previous,
                };
                if retained.take().is_some() {
                    self.journal.save(&installation_id, slot)?;
                }
            }
            Command::Purge { installation_id } => self.purge(&installation_id).await?,
            Command::Activate {
                installation_id,
                grants,
            } => {
                if grants.len() > 256 {
                    return Err(bad("Too many requested grants"));
                }
                let target = self
                    .journal
                    .slot(&installation_id)?
                    .candidate
                    .clone()
                    .ok_or_else(|| bad("No staged candidate"))?;
                self.switch(&installation_id, target, Some(&grants)).await?;
            }
            Command::Rollback { installation_id } => {
                let target = self
                    .journal
                    .slot(&installation_id)?
                    .previous
                    .clone()
                    .ok_or_else(|| bad("No retained previous release"))?;
                self.switch(&installation_id, target, Some(&[])).await?;
            }
            Command::Stop { installation_id } => {
                self.stop(&installation_id).await?;
            }
            Command::Start { installation_id } => {
                if let Some(live) = self.running.get_mut(&installation_id) {
                    if !live.exited()? {
                        return Ok(Value::Null);
                    }
                    let mut slot = self.journal.slot(&installation_id)?.clone();
                    slot.require_recovery();
                    self.journal.save(&installation_id, slot)?;
                    self.fence(&installation_id).await?;
                }
                let slot = self.journal.slot(&installation_id)?;
                let target = slot
                    .active
                    .clone()
                    .ok_or_else(|| bad("No committed release"))?;
                let grants = slot.uncertain_grants().then_some([].as_slice());
                self.switch(&installation_id, target, grants).await?;
            }
        }
        Ok(Value::Null)
    }

    async fn reconcile(&mut self) -> io::Result<()> {
        // Share extra attempts across the boot. Healthy starts do not consume the budget.
        let mut lock_retries = 7;
        let slots: Vec<_> = self.journal.slots().keys().cloned().collect();
        for id in slots {
            let mut slot = self.journal.slot(&id)?.clone();
            let result = async {
                match slot.removal {
                    Removal::Removing => return self.remove(&id).await,
                    Removal::Purging => return self.purge(&id).await,
                    Removal::Removed | Removal::Purged => return Ok(()),
                    Removal::Installed => (),
                }
                self.fence(&id).await?;
                if slot.desired_running {
                    let target = slot
                        .active
                        .take()
                        .ok_or_else(|| bad("No active release to recover"))?;
                    self.launch(
                        &id,
                        target,
                        slot.uncertain_grants().then_some([].as_slice()),
                        Some(&mut lock_retries),
                    )
                    .await?;
                }
                Ok::<_, io::Error>(())
            }
            .await;
            if let Err(e) = result {
                let mut slot = self.journal.slot(&id)?.clone();
                slot.require_recovery();
                self.journal.save(&id, slot)?;
                eprintln!("Installation {id} needs recovery: {e}");
            }
        }
        Ok(())
    }

    async fn serve(&mut self) -> io::Result<()> {
        let listener = Arc::new(control::bind()?);
        self.listener = Some(Arc::clone(&listener));
        self.reconcile().await?;
        let mut tick = tokio::time::interval(Duration::from_secs(2));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = tick.tick() => self.check_exits().await?,
                connection = listener.accept() => self.reply(connection?.0).await?,
            }
        }
    }

    /// After an unexpected exit, ticks retry retirement and leave the app stopped for manual recovery with `start`.
    /// The next manager boot reconciles the saved running intent.
    async fn check_exits(&mut self) -> io::Result<()> {
        self.check_other_exits(None).await
    }

    async fn check_other_exits(&mut self, busy: Option<&str>) -> io::Result<()> {
        let pending: Vec<_> = self
            .journal
            .slots()
            .iter()
            .filter(|(id, s)| {
                Some(id.as_str()) != busy && s.pending_fence && !self.running.contains_key(*id)
            })
            .map(|(id, _)| id.clone())
            .collect();
        let start = pending.partition_point(|id| id <= &self.fence_cursor);
        let retry = pending[start..].iter().chain(&pending[..start]).take(8);
        let mut dead = Vec::new();
        for (id, live) in &mut self.running {
            if Some(id.as_str()) != busy && live.exited()? {
                dead.push(id.clone());
            }
        }
        for id in &dead {
            let mut slot = self.journal.slot(id)?.clone();
            slot.require_recovery();
            self.journal.save(id, slot)?;
        }
        for id in retry {
            self.fence_cursor.clone_from(id);
            dead.push(id.clone());
        }
        if let Err(error) = self.drain_slots(dead).await {
            eprintln!("Application retirement pending: {error}");
        }
        Ok(())
    }

    async fn reply(&mut self, mut stream: tokio::net::UnixStream) -> io::Result<()> {
        let result = match control::read(&mut stream).await {
            Ok(request) => self.execute(request).await,
            Err(error) => Err(error),
        };
        Self::respond(&mut stream, result).await
    }

    async fn respond(
        stream: &mut tokio::net::UnixStream,
        result: io::Result<Value>,
    ) -> io::Result<()> {
        let response = match result {
            Ok(value) => json!({"ok": true, "result": value}),
            Err(error) => json!({"ok": false, "error": error.to_string()}),
        };
        let bytes = serde_json::to_vec(&response)?;
        let _ = timeout(Duration::from_secs(2), stream.write_all(&bytes)).await;
        Ok(())
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        let pending: Vec<_> = self
            .journal
            .slots()
            .iter()
            .filter(|(id, s)| s.pending_fence || self.running.contains_key(*id))
            .map(|(id, _)| id.clone())
            .collect();
        self.drain_slots(pending).await
    }

    async fn drain_slots(&mut self, ids: Vec<String>) -> io::Result<()> {
        let mut jobs = JoinSet::new();
        for id in ids {
            let slot = self.journal.slot(&id)?.clone();
            let path = self.journal.writer_path(slot.uid);
            let gateway = self.gateway.clone();
            let mut live = self.running.remove(&id);
            if let Some(live) = &mut live {
                live.close();
            }
            jobs.spawn(async move {
                let fenced = timeout(DRAIN_IO_BUDGET, async {
                    // Authority can be withdrawn as the broker exits. A provisioning writer
                    // could re-enable its DB role, so confirm writer and UID retirement first.
                    let (broker, database, authority) = tokio::join!(
                        async {
                            if let Some(live) = live {
                                live.stop().await?;
                            }
                            Ok::<_, io::Error>(())
                        },
                        async {
                            let _guard = Self::wait_writer(path, slot.uid).await?;
                            if slot.pending_fence {
                                Self::retire_database(&slot).await?;
                            }
                            Ok::<_, io::Error>(())
                        },
                        async {
                            if slot.pending_fence {
                                Self::retire_authority(&gateway, &id, &slot).await?;
                            }
                            Ok::<_, io::Error>(())
                        }
                    );
                    broker?;
                    database?;
                    authority
                })
                .await
                .map_err(io::Error::from)
                .and_then(|result| result);
                (id, slot, fenced)
            });
        }
        let mut failures = Vec::new();
        while let Some(job) = jobs.join_next().await {
            match job {
                Ok((id, mut slot, fenced)) => match fenced {
                    Ok(()) if slot.pending_fence => {
                        slot.pending_fence = false;
                        slot.authority_recorded = Some(true);
                        if let Err(e) = self.journal.save(&id, slot) {
                            failures.push(format!("{id} journal: {e}"));
                        }
                    }
                    Ok(()) => (),
                    Err(e) => failures.push(format!("{id} fence: {e}")),
                },
                Err(e) => failures.push(e.to_string()),
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(io::Error::other(failures.join("; ")))
        }
    }
}

fn recover(installer: &Installer, app: &str, record: &Release) -> io::Result<StagedPackage> {
    let package = installer.recover(app, &record.version, &record.archive_sha256)?;
    if package.manifest_sha256 != record.manifest_sha256
        || package.archive_sha256 != record.archive_sha256
        || package.catalog_revision < record.catalog_revision
        || package.manifest["id"] != app
        || package.manifest["version"] != record.version
    {
        return Err(bad("Recovered package differs from recorded release"));
    }
    Ok(package)
}

pub(crate) fn backup_inventory(config: Option<&Path>) -> io::Result<(impl Sized, Value)> {
    let journal = Journal::open(Path::new("/var/lib/rentnerproxy/app-manager"))?;
    let mut installer = None;
    let mut writers = Vec::new();
    for slot in journal.slots().values() {
        writers.push(journal.writer(slot.uid)?);
        if slot.pending_fence
            || slot.database_provisioned
            || slot.recovery_required
            || matches!(slot.removal, Removal::Removing | Removal::Purging)
        {
            return Err(bad(
                "App installation requires repair or unsupported backup handling",
            ));
        }
        for release in [&slot.active, &slot.candidate, &slot.previous]
            .into_iter()
            .flatten()
        {
            let installer = match &mut installer {
                Some(existing) => existing,
                empty => empty.insert(Installer::open(
                    config.ok_or_else(|| bad("Missing installer configuration for backup"))?,
                )?),
            };
            recover(installer, &slot.app_id, release)?;
        }
    }
    let snapshot = serde_json::to_value(journal.slots())?;
    Ok(((journal, writers), snapshot))
}

fn read_data(value: &Value) -> io::Result<Data> {
    let integer = |v: &Value| {
        v.as_f64()
            .filter(|n| n.fract() == 0.0 && (0.0..=i32::MAX as f64).contains(n))
            .map(|n| n as u32)
            .ok_or_else(|| bad("Invalid data version"))
    };
    let versions = |k: &str| {
        value[k]
            .as_array()
            .ok_or_else(|| bad("Missing data versions"))?
            .iter()
            .map(integer)
            .collect::<io::Result<Vec<_>>>()
    };
    Ok(Data {
        target_version: integer(&value["targetVersion"])?,
        read_versions: versions("readVersions")?,
        write_versions: versions("writeVersions")?,
        migrations: value["migrations"]
            .as_array()
            .ok_or_else(|| bad("Missing migrations"))?
            .clone(),
    })
}

fn exit(result: io::Result<()>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("App manager: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn boot(mut arguments: impl Iterator<Item = String>) -> io::Result<()> {
    let config = PathBuf::from(
        arguments
            .next()
            .ok_or_else(|| bad("Expected installer configuration path"))?,
    );
    if arguments.next().is_some() || unsafe { libc::geteuid() } != 0 {
        return Err(bad(
            "App manager requires root and one installer configuration",
        ));
    }
    let check = config.clone();
    tokio::task::spawn_blocking(move || Installer::open(&check).map(drop)).await??;
    let mut manager = Manager {
        listener: None,
        config,
        journal: Journal::open(Path::new("/var/lib/rentnerproxy/app-manager"))?,
        gateway: Gateway::open()?,
        running: BTreeMap::new(),
        fence_cursor: String::new(),
    };
    let result = tokio::select! {
        biased;
        _ = crate::shutdown::wait_for_shutdown() => Ok(()),
        result = manager.serve() => result,
    };
    timeout(SHUTDOWN_BUDGET, manager.shutdown()).await??;
    result
}

pub async fn run_app_manager(arguments: impl Iterator<Item = String>) -> ExitCode {
    exit(boot(arguments).await)
}
