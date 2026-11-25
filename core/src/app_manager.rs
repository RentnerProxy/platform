mod catalog;
mod control;
mod gateway;
mod journal;
mod lifecycle;
mod migration;
pub(crate) mod portable_backup;
mod removal;
mod runtime;
mod service;
mod storage;
#[cfg(test)]
#[path = "../tests/private/app_manager.rs"]
mod tests;
mod ui;

use crate::app_install::{Installer, StagedPackage};
use crate::appliance_process::{SCAN_BUDGET, uid_in_use, verify_uid_stopped};
use control::Command;
pub use control::run_app_control;
use gateway::{Gateway, identity, lease};
use journal::{Data, DataChange, Grant, Journal, Release, Removal, Slot};
use runtime::Running;
use serde_json::{Value, json};
use service::Operation;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fs::File,
    io,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::AsyncWriteExt,
    net::UnixStream,
    sync::{mpsc, watch},
    task::{Id, JoinError, JoinSet},
    time::{Instant, sleep, timeout, timeout_at},
};

const MAX_GENERATION: u64 = 9_007_199_254_740_991;
// The supervisor permits 18 s. Leave 500 ms for the journal and 250 ms for exit.
const DRAIN_IO_BUDGET: Duration = Duration::from_millis(17_250);
const SHUTDOWN_BUDGET: Duration = Duration::from_millis(17_750);
const SCAN_ADMISSION_MARGIN: Duration = Duration::from_millis(50);

/// Whether an activation may run the declared data migrations of its release. Restarts,
/// rollbacks and recovery only open data that the release can already read and write.
#[derive(Clone, Copy, Eq, PartialEq)]
enum DataPolicy {
    Migrate,
    OpenOnly,
}

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
    config: Option<PathBuf>,
    journal: Journal,
    gateway: Gateway,
    ui: ui::Registry,
    running: BTreeMap<String, Running>,
    fence_cursor: String,
    drains: JoinSet<io::Result<()>>,
    draining: HashMap<Id, Drain>,
}

enum PackageRequest {
    Current,
    Selected(String),
    Recorded(Release),
}

struct Drain {
    installation_id: String,
    uid: u32,
    generation: u64,
    fencing_authority: bool,
    stop_reply: Option<UnixStream>,
    cutoff: watch::Sender<Instant>,
}

impl Drain {
    fn matches_pending(&self, slot: &Slot) -> bool {
        slot.uid == self.uid && slot.generation == self.generation && slot.pending_fence
    }
}

impl Manager {
    async fn package(
        config: Option<PathBuf>,
        app: String,
        version: String,
        request: PackageRequest,
    ) -> io::Result<StagedPackage> {
        let (send, result) = tokio::sync::oneshot::channel();
        // Catalog downloads may outlive a shutdown request. Only the async owner publishes journal transitions.
        std::thread::Builder::new()
            .name("app-package".into())
            .spawn(move || {
                let _ = send.send((|| {
                    let installer = Installer::open_appliance(config.as_deref())?;
                    let package = match request {
                        PackageRequest::Current => installer.stage(&app, &version)?,
                        PackageRequest::Selected(digest) => {
                            installer.stage_selected(&app, &version, &digest)?
                        }
                        PackageRequest::Recorded(record) => recover(&installer, &app, &record)?,
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
        Self::wait_writer(self.journal.writer_path(uid), None, move || {
            verify_uid_stopped(uid)
        })
        .await
    }

    fn scan_fits(cutoff: Instant) -> bool {
        cutoff.saturating_duration_since(Instant::now()) >= SCAN_BUDGET + SCAN_ADMISSION_MARGIN
    }

    fn require_scan_budget(deadline: Option<&watch::Receiver<Instant>>) -> io::Result<()> {
        if deadline.is_some_and(|deadline| !Self::scan_fits(*deadline.borrow())) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Insufficient drain time for a UID scan",
            ));
        }
        Ok(())
    }

    async fn wait_writer(
        path: PathBuf,
        deadline: Option<watch::Receiver<Instant>>,
        verify: impl Fn() -> io::Result<()> + Clone + Send + 'static,
    ) -> io::Result<File> {
        timeout(Duration::from_secs(11), async {
            loop {
                match journal::lock(&path) {
                    Ok(mut file) => {
                        let mut scans = JoinSet::new();
                        loop {
                            Self::require_scan_budget(deadline.as_ref())?;
                            let queued_deadline = deadline.clone();
                            let verify = verify.clone();
                            scans.spawn_blocking(move || {
                                // Dropping the task set cancels a queued scan. A scan
                                // already running retains the writer until it exits.
                                let result = Self::require_scan_budget(queued_deadline.as_ref())
                                    .and_then(|()| verify());
                                (file, result)
                            });
                            let (locked, result) = scans.join_next().await.expect("queued scan")?;
                            file = locked;
                            match result {
                                Ok(()) => return Ok(file),
                                // A changing thread list needs a fresh, conclusive scan.
                                Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                                    sleep(Duration::from_millis(100)).await
                                }
                                Err(e) => return Err(e),
                            }
                        }
                    }
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
            slot.acknowledge_fence();
            self.journal.save(id, slot)?;
        }
        Ok(writer)
    }

    async fn retire(gateway: &Gateway, id: &str, slot: &Slot) -> io::Result<()> {
        let (authority, database) = tokio::join!(
            Self::retire_authority(gateway, json!({"identity":identity(id,slot)})),
            Self::retire_database(slot.uid, slot.database_provisioned)
        );
        database?;
        authority
    }

    async fn retire_database(uid: u32, provisioned: bool) -> io::Result<()> {
        if provisioned {
            runtime::fence_database(uid).await?;
        }
        Ok(())
    }

    async fn retire_authority(gateway: &Gateway, body: Value) -> io::Result<()> {
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
        policy: DataPolicy,
        mut boot_lock_retries: Option<&mut usize>,
    ) -> io::Result<()> {
        let slot = self.journal.slot(id)?.clone();
        // Historical committed generations predate the explicit storage acknowledgement.
        let committed_data = slot.active.is_some()
            && (slot.generation > 0 || slot.storage_claimed == Some(true))
            || slot.removal == Removal::Removed
                && slot
                    .removed_data_required
                    .unwrap_or(slot.generation > 0 && slot.storage_claimed != Some(false));
        let admit_storage = || {
            if committed_data {
                storage::require_data(id, &slot)
                    .map_err(|e| io::Error::new(e.kind(), storage::CommittedDataUnavailable(e)))?;
            }
            Ok::<_, io::Error>(())
        };
        admit_storage()?;
        let config = self.config.clone();
        let package = self
            .during(Operation::Launch(id), async {
                loop {
                    let result = Self::package(
                        config.clone(),
                        slot.app_id.clone(),
                        release.version.clone(),
                        PackageRequest::Recorded(release.clone()),
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
        // Only a migration changes the recorded version, and none runs while this generation
        // lives, so reading it before the fence lets an incompatible release leave it running.
        let recorded = if slot.database_provisioned {
            self.during(
                Operation::Launch(id),
                migration::recorded_version(slot.uid),
            )
            .await?
        } else {
            None
        };
        let change = slot
            .plan(&release, data.as_ref(), recorded)
            .filter(|change| policy == DataPolicy::Migrate || *change == DataChange::Keep)
            .ok_or_else(|| io::Error::other(lifecycle::IncompatibleData))?;
        let generation = slot
            .generation
            .checked_add(1)
            .filter(|n| *n <= MAX_GENERATION)
            .ok_or_else(|| bad("Generation limit reached"))?;
        let ui_id = id.to_owned();
        let uid = slot.uid;
        let (package, ui_package) = self
            .during(Operation::Launch(id), async move {
                tokio::task::spawn_blocking(move || {
                    let ui = ui::Package::load(&package, ui_id, generation, uid);
                    (package, ui)
                })
                .await
                .map_err(io::Error::other)
            })
            .await?;
        let ui_package = match ui_package {
            Ok(package) => package,
            Err(_) => {
                eprintln!("Application {id} UI package unavailable");
                None
            }
        };
        let writer = self.fence(id).await?;
        // The old UID can change its own data directory's mode until its fence completes.
        admit_storage()?;
        let mut slot = self.journal.slot(id)?.clone();
        slot.generation = generation;
        slot.require_recovery();
        slot.pending_fence = true;
        self.journal.save(id, slot.clone())?;
        let who = identity(id, &slot);
        let (mut registration, deadline) = lease(&who)?;
        registration["capabilities"] = package.manifest["capabilities"].clone();
        registration["permissionKeys"] = package.manifest["permissions"].clone();
        registration["providerProfiles"] = package
            .manifest
            .get("providers")
            .cloned()
            .unwrap_or_else(|| json!([]));
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
        if !committed_data {
            if slot.storage_claimed == Some(false) {
                slot.storage_claimed = None;
                self.journal.save(id, slot.clone())?;
            }
            storage::claim(id, &slot)?;
        }
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
        if slot.removal == Removal::Removed {
            // For a reinstall after purge, only completed provisioning creates a data directory.
            slot.removed_data_required = Some(true);
        }
        if let DataChange::Migrate(steps) = &change {
            // A failed step leaves the data untouched, so the fallback can restart the old release.
            self.during(
                Operation::Launch(id),
                migration::apply(slot.uid, &package.directory, steps),
            )
            .await?;
        }
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
        slot.removal = Removal::Installed;
        slot.removed_release = None;
        slot.removed_data_required = None;
        slot.desired_running = true;
        slot.recovery_required = false;
        slot.grants_uncertain = None;
        self.journal.save(id, slot)?;
        live.ui = ui_package.and_then(|package| self.ui.publish(package));
        self.running.insert(id.to_owned(), live);
        Ok(())
    }

    async fn switch(
        &mut self,
        id: &str,
        target: Release,
        grants: Option<&[Grant]>,
        policy: DataPolicy,
    ) -> io::Result<()> {
        let before = self.journal.slot(id)?.clone();
        match self.launch(id, target, grants, policy, None).await {
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
                    // After a completed migration the old release usually cannot open the data,
                    // which leaves the installation in recovery instead of losing those writes.
                    if self
                        .launch(
                            id,
                            active,
                            uncertain.then_some([].as_slice()),
                            DataPolicy::OpenOnly,
                            None,
                        )
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
            && !matches!(cmd, Command::Stage { .. } | Command::Stop { .. })
        {
            self.settle_exit(id).await?;
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
                let download = Self::package(
                    self.config.clone(),
                    app_id.clone(),
                    version.clone(),
                    PackageRequest::Current,
                );
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
                self.switch(
                    &installation_id,
                    target,
                    Some(&grants),
                    DataPolicy::Migrate,
                )
                .await?;
            }
            Command::Rollback { installation_id } => {
                let target = self
                    .journal
                    .slot(&installation_id)?
                    .previous
                    .clone()
                    .ok_or_else(|| bad("No retained previous release"))?;
                self.switch(&installation_id, target, Some(&[]), DataPolicy::OpenOnly)
                    .await?;
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
                let candidate = slot.candidate.clone();
                let grants = slot.uncertain_grants().then_some([].as_slice());
                let result = self
                    .switch(&installation_id, target, grants, DataPolicy::OpenOnly)
                    .await;
                match (result, candidate) {
                    // A migration that committed before its activation failed leaves data only
                    // the staged release can open. Recovery finishes that update without migrating.
                    (Err(error), Some(candidate)) if lifecycle::incompatible(&error) => {
                        self.switch(&installation_id, candidate, grants, DataPolicy::OpenOnly)
                            .await?;
                    }
                    (result, _) => result?,
                }
            }
        }
        Ok(Value::Null)
    }

    async fn reconcile(&mut self) -> io::Result<()> {
        // Share extra attempts across the boot. Healthy starts do not consume the budget.
        let mut lock_retries = 7;
        let slots: Vec<_> = self.journal.slots().keys().cloned().collect();
        for id in slots {
            self.settle_exit(&id).await?;
            let mut slot = self.journal.slot(&id)?.clone();
            let result = async {
                match slot.removal {
                    Removal::Removing => return self.remove(&id).await,
                    Removal::Purging => return self.purge(&id).await,
                    Removal::Removed | Removal::Purged => {
                        if slot.pending_fence {
                            self.fence(&id).await?;
                        }
                        return Ok(());
                    }
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
                        DataPolicy::OpenOnly,
                        Some(&mut lock_retries),
                    )
                    .await?;
                }
                Ok::<_, io::Error>(())
            }
            .await;
            if let Err(e) = result {
                if e.get_ref()
                    .is_some_and(|cause| cause.is::<storage::CommittedDataUnavailable>())
                {
                    // Boot already fenced this slot. Its release and grants still match an offline repair.
                    eprintln!("Installation {id} remains stopped: {e}");
                    continue;
                }
                let mut slot = self.journal.slot(&id)?.clone();
                slot.require_recovery();
                self.journal.save(&id, slot)?;
                eprintln!("Installation {id} needs recovery: {e}");
            }
        }
        Ok(())
    }

    async fn serve(
        &mut self,
        catalog: &catalog::Endpoint,
        requests: &mut mpsc::Receiver<catalog::Request>,
    ) -> io::Result<()> {
        let listener = Arc::new(control::bind()?);
        self.listener = Some(Arc::clone(&listener));
        self.reconcile().await?;
        if self.config.is_none()
            && let Err(error) = catalog.refresh()
        {
            eprintln!("Could not start application catalog refresh: {error}");
        }
        self.serve_control(&listener, catalog, requests).await
    }

    async fn serve_control(
        &mut self,
        listener: &tokio::net::UnixListener,
        catalog: &catalog::Endpoint,
        requests: &mut mpsc::Receiver<catalog::Request>,
    ) -> io::Result<()> {
        let mut tick = tokio::time::interval(Duration::from_secs(2));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            catalog.publish(self.local_installations())?;
            tokio::select! {
                _ = tick.tick() => self.check_exits(None)?,
                Some(job) = self.drains.join_next_with_id(), if !self.drains.is_empty() => {
                    self.report_exit(job).await?;
                }
                Some(request) = requests.recv() => {
                    match request {
                        catalog::Request::Install(selection) => {
                            let result = self.install_catalog(&selection).await;
                            catalog.publish(self.local_installations())?;
                            catalog.finish(selection, result)?;
                        }
                        catalog::Request::Lifecycle(request) => {
                            let result = self.manage_lifecycle(&request).await;
                            catalog.publish(self.local_installations())?;
                            catalog.finish_lifecycle(request, result)?;
                        }
                    }
                    self.journal.writable()?;
                }
                connection = listener.accept() => self.reply(connection?.0).await?,
            }
        }
    }

    /// After an unexpected exit, ticks retry retirement and leave the app stopped for manual recovery with `start`.
    /// The next manager boot reconciles the saved running intent.
    fn check_exits(&mut self, busy: Option<&str>) -> io::Result<()> {
        let pending: Vec<_> = self
            .journal
            .slots()
            .iter()
            .filter(|(id, s)| {
                Some(id.as_str()) != busy
                    && s.pending_fence
                    && !self.running.contains_key(*id)
                    && !self.is_draining(id)
            })
            .map(|(id, _)| id.clone())
            .collect();
        let start = pending.partition_point(|id| id <= &self.fence_cursor);
        // Keep the retry budget across ticks while earlier drains are still in flight.
        let retry = pending[start..]
            .iter()
            .chain(&pending[..start])
            .take(8usize.saturating_sub(self.drains.len()));
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
        let cutoff = Instant::now() + DRAIN_IO_BUDGET;
        for id in dead {
            self.begin_drain(id, cutoff)?;
        }
        Ok(())
    }

    async fn reply(&mut self, mut stream: UnixStream) -> io::Result<()> {
        let request = control::read(&mut stream)
            .await
            .and_then(|request| self.admit_request(request, None, true));
        let result = match request {
            Ok(Command::Stop { installation_id }) => {
                return self.defer_stop(installation_id, stream).await;
            }
            Ok(request) => self.execute(request).await,
            Err(error) => Err(error),
        };
        Self::respond(&mut stream, result).await
    }

    async fn respond(
        stream: &mut UnixStream,
        result: Result<Value, impl std::fmt::Display>,
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
        let start = Instant::now();
        let journal_deadline = start + SHUTDOWN_BUDGET;
        timeout_at(
            journal_deadline,
            self.shutdown_drains(start + DRAIN_IO_BUDGET, journal_deadline),
        )
        .await?
    }

    async fn shutdown_drains(
        &mut self,
        cutoff: Instant,
        journal_deadline: Instant,
    ) -> io::Result<()> {
        // A shutdown closes any in-flight control connection. The accepted stop
        // intent is already durable, and the drain still needs to settle.
        let mut inherited: HashSet<_> = self
            .draining
            .iter_mut()
            .map(|(task, drain)| {
                drain.stop_reply = None;
                drain.cutoff.send_replace(cutoff);
                *task
            })
            .collect();
        let pending: Vec<_> = self
            .journal
            .slots()
            .iter()
            .filter(|(id, s)| {
                (s.pending_fence || self.running.contains_key(*id)) && !self.is_draining(id)
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in pending {
            self.begin_drain(id, cutoff)?;
        }
        let mut failures = Vec::new();
        let mut acknowledgments = BTreeSet::new();
        let mut journal_write = None;
        let mut journal_failed = false;
        let mut ready = None;
        loop {
            if let Some(job) = ready.take().or_else(|| self.drains.try_join_next_with_id()) {
                let (task, drain, result) = self.take_drain_result(job);
                let was_inherited = inherited.remove(&task);
                let id = &drain.installation_id;
                let result = result.and_then(|()| self.fenced_slot(&drain));
                match result {
                    Ok(Some(_)) => {
                        acknowledgments.insert(drain.installation_id);
                    }
                    Ok(None) => (),
                    Err(_)
                        if was_inherited
                            && Self::scan_fits(cutoff)
                            // An in-flight write has only acknowledged other slots.
                            && (journal_write.is_some() || self.journal.writable().is_ok())
                            && self
                                .journal
                                .slot(id)
                                .is_ok_and(|slot| drain.matches_pending(slot)) =>
                    {
                        self.begin_drain(drain.installation_id, cutoff)?;
                    }
                    Err(error) => failures.push(format!("{id} fence: {error}")),
                }
                continue;
            }
            // Save ready acknowledgments together without waiting for slower fences.
            if journal_write.is_none() && !journal_failed && !acknowledgments.is_empty() {
                match self
                    .journal
                    .begin_shutdown_save(std::mem::take(&mut acknowledgments), journal_deadline)
                {
                    Ok(write) => journal_write = Some(write),
                    Err(error) => {
                        journal_failed = true;
                        failures.push(format!("Shutdown journal: {error}"));
                    }
                }
            }
            if self.drains.is_empty() && journal_write.is_none() {
                break;
            }
            tokio::select! {
                result = async {
                    journal_write.as_mut().expect("pending shutdown write").wait().await
                }, if journal_write.is_some() => {
                    journal_write = None;
                    match result {
                        Ok(commit) => self.journal.complete_shutdown_save(commit),
                        Err(error) => {
                            journal_failed = true;
                            failures.push(format!("Shutdown journal: {error}"));
                        }
                    }
                }
                job = self.drains.join_next_with_id(), if !self.drains.is_empty() => ready = job,
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(io::Error::other(failures.join("; ")))
        }
    }

    fn is_draining(&self, id: &str) -> bool {
        self.drain_task(id).is_some()
    }

    fn drain_task(&self, id: &str) -> Option<Id> {
        self.draining
            .iter()
            .find_map(|(task, drain)| (drain.installation_id == id).then_some(*task))
    }

    fn begin_drain(&mut self, id: String, cutoff: Instant) -> io::Result<Id> {
        let slot = self.journal.slot(&id)?;
        let uid = slot.uid;
        let path = self.journal.writer_path(uid);
        let fencing_authority = slot.pending_fence;
        let fence_database = fencing_authority && slot.database_provisioned;
        let authority_request = fencing_authority.then(|| json!({"identity":identity(&id,slot)}));
        let gateway = self.gateway.clone();
        let mut live = self.running.remove(&id);
        if let Some(live) = &mut live {
            live.close();
        }
        let (cutoff, deadline) = watch::channel(cutoff);
        let writer_deadline = deadline.clone();
        let drain = Drain {
            installation_id: id,
            uid,
            generation: slot.generation,
            fencing_authority,
            stop_reply: None,
            cutoff,
        };
        let task = self.drains.spawn(Self::drain_until(deadline, async move {
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
                    let _guard = Self::wait_writer(path, Some(writer_deadline), move || {
                        verify_uid_stopped(uid)
                    })
                    .await?;
                    // PostgreSQL uses the time remaining before the shared cutoff.
                    Self::retire_database(uid, fence_database).await
                },
                async {
                    if let Some(body) = authority_request {
                        Self::retire_authority(&gateway, body).await?;
                    }
                    Ok::<_, io::Error>(())
                }
            );
            broker?;
            database?;
            authority
        }));
        self.draining.insert(task.id(), drain);
        Ok(task.id())
    }

    async fn drain_until<T>(
        mut deadline: watch::Receiver<Instant>,
        work: impl Future<Output = io::Result<T>>,
    ) -> io::Result<T> {
        // Updating an inherited deadline must neither restart nor cancel its work.
        tokio::pin!(work);
        loop {
            let cutoff = *deadline.borrow_and_update();
            tokio::select! {
                biased;
                change = deadline.changed() => change.map_err(io::Error::other)?,
                result = timeout_at(cutoff, &mut work) => match result {
                    Ok(result) => return result,
                    Err(error) if *deadline.borrow() <= cutoff => return Err(error.into()),
                    // The new deadline may arrive after the change branch was polled.
                    Err(_) => continue,
                },
            }
        }
    }

    fn take_drain_result(
        &mut self,
        job: Result<(Id, io::Result<()>), JoinError>,
    ) -> (Id, Drain, io::Result<()>) {
        let (task, result) = match job {
            Ok(result) => result,
            Err(error) => (error.id(), Err(error.into())),
        };
        let drain = self.draining.remove(&task).expect("tracked drain task");
        (task, drain, result)
    }

    fn fenced_slot(&self, drain: &Drain) -> io::Result<Option<&Slot>> {
        let id = &drain.installation_id;
        let slot = self.journal.slot(id)?;
        // Staging can publish a candidate while the existing generation drains.
        Ok((drain.fencing_authority && drain.matches_pending(slot)).then_some(slot))
    }

    async fn finish_control_drain(
        &mut self,
        job: Result<(Id, io::Result<()>), JoinError>,
    ) -> (String, io::Result<()>) {
        let (_, drain, result) = self.take_drain_result(job);
        let result = result.and_then(|()| {
            if let Some(slot) = self.fenced_slot(&drain)? {
                let mut slot = slot.clone();
                slot.acknowledge_fence();
                self.journal.save(&drain.installation_id, slot)?;
            }
            Ok(())
        });
        if let Some(mut stream) = drain.stop_reply
            && let Err(error) =
                Self::respond(&mut stream, result.as_ref().map(|()| Value::Null)).await
        {
            eprintln!("Application stop reply failed: {error}");
        }
        (drain.installation_id, result)
    }

    async fn report_exit(
        &mut self,
        job: Result<(Id, io::Result<()>), JoinError>,
    ) -> io::Result<()> {
        let (id, result) = self.finish_control_drain(job).await;
        if let Err(error) = result {
            eprintln!("Application {id} retirement pending: {error}");
        }
        self.journal.writable()
    }

    async fn wait_for_drain(&mut self, id: &str) -> io::Result<()> {
        if self.is_draining(id) {
            while let Some(job) = self.drains.join_next_with_id().await {
                let (completed, result) = self.finish_control_drain(job).await;
                if completed == id {
                    return result;
                }
                if let Err(error) = result {
                    eprintln!("Application {completed} retirement pending: {error}");
                }
                self.journal.writable()?;
            }
        }
        Ok(())
    }

    async fn settle_exit(&mut self, id: &str) -> io::Result<()> {
        if let Err(error) = self.wait_for_drain(id).await {
            eprintln!("Application {id} retirement pending: {error}");
        }
        self.journal.writable()
    }
}

fn recover(installer: &Installer, app: &str, record: &Release) -> io::Result<StagedPackage> {
    let package = installer.recover(app, &record.version, &record.archive_sha256)?;
    verify_recovered_release(&package, app, record)?;
    Ok(package)
}

fn verify_recovered_release(
    package: &StagedPackage,
    app: &str,
    record: &Release,
) -> io::Result<()> {
    if package.manifest_sha256 != record.manifest_sha256
        || package.archive_sha256 != record.archive_sha256
        || package.catalog_revision < record.catalog_revision
        || package.manifest["id"] != app
        || package.manifest["version"] != record.version
    {
        return Err(bad("Recovered package differs from recorded release"));
    }
    Ok(())
}

pub(crate) fn backup_inventory(config: Option<&Path>) -> io::Result<(impl Sized, Value)> {
    let journal = Journal::open(Path::new("/var/lib/rentnerproxy/app-manager"))?;
    portable_backup::require_ready_to_start()?;
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
                empty => empty.insert(Installer::open_appliance(config)?),
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
    let config = arguments
        .next()
        .map(PathBuf::from)
        .or_else(Installer::appliance_override);
    if arguments.next().is_some() || unsafe { libc::geteuid() } != 0 {
        return Err(bad(
            "App manager requires root and accepts at most one installer configuration",
        ));
    }
    let check = config.clone();
    tokio::task::spawn_blocking(move || Installer::open_appliance(check.as_deref()).map(|_| ()))
        .await??;
    let (catalog, mut installations) = catalog::Endpoint::new(config.clone());
    let ui_catalog = catalog.clone();
    let ui = ui::Registry::default();
    let mut manager = Manager {
        listener: None,
        config,
        journal: Journal::open(Path::new("/var/lib/rentnerproxy/app-manager"))?,
        gateway: Gateway::open()?,
        ui: ui.clone(),
        running: BTreeMap::new(),
        fence_cursor: String::new(),
        drains: JoinSet::new(),
        draining: HashMap::new(),
    };
    portable_backup::require_ready_to_start()?;
    let result = tokio::select! {
        biased;
        _ = crate::shutdown::wait_for_shutdown() => Ok(()),
        result = manager.serve(&catalog, &mut installations) => result,
        () = async move {
            let result = match ui::bind() {
                Ok(listener) => ui::serve(listener, ui, ui_catalog).await,
                Err(error) => Err(error),
            };
            if let Err(error) = result {
                eprintln!("Application UI service unavailable: {error}");
            }
            std::future::pending::<()>().await;
        } => Ok(()),
    };
    manager.shutdown().await?;
    result
}

pub async fn run_app_manager(arguments: impl Iterator<Item = String>) -> ExitCode {
    exit(boot(arguments).await)
}
