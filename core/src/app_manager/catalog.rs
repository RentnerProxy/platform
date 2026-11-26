use std::{
    io,
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use marketplace_artifacts::digest;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use super::{
    Command, Manager, PackageRequest, gate,
    journal::{Release, Removal},
    lifecycle,
};
use crate::app_install::{
    CatalogEntry, Installer, Source, TargetEnvironment,
    grants::{self, ApprovedGrant, MAX_GRANTS},
    unreachable_source,
};

#[cfg(test)]
#[path = "../../tests/private/app_manager/catalog.rs"]
pub(super) mod tests;

const REFRESH_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Selection {
    app_id: String,
    version: String,
    archive_sha256: String,
    /// The Owner's approval of the grants this release requests. Receipts never repeat it.
    #[serde(default, skip_serializing)]
    approval: Option<Vec<ApprovedGrant>>,
}

impl Selection {
    fn matches(&self, release: &Release) -> bool {
        release.version == self.version && release.archive_sha256 == self.archive_sha256
    }

    /// The installation ID a first catalog install of this app receives.
    fn installation_id(&self) -> String {
        format!("app-{}", &digest(self.app_id.as_bytes())[..32])
    }

    pub(super) fn valid(&self) -> bool {
        self.approval
            .as_ref()
            .is_none_or(|approval| approval.len() <= MAX_GRANTS)
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) enum Failure {
    Conflict,
    /// The release needs an approval of exactly the grants it requests.
    ApprovalRequired,
    Unavailable,
    /// The signed catalog metadata could not be reached, but the package source answered.
    CatalogUnavailable,
    /// Fresh signed metadata arrived, but the package source did not answer.
    PackageSourceUnavailable,
    /// Neither the catalog nor the package source answered.
    NetworkUnavailable,
    InstallFailed,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) enum Request {
    Install(Selection),
    Lifecycle(lifecycle::Request),
}

#[derive(Clone, Serialize)]
#[serde(
    tag = "status",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
enum InstallStatus {
    Installing,
    Installed { installation_id: String },
    Failed { error: Failure },
}

#[derive(Clone, Serialize)]
pub(super) struct Install {
    #[serde(flatten)]
    selection: Selection,
    #[serde(flatten)]
    status: InstallStatus,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
enum LifecycleFailure {
    Conflict,
    /// The target release needs an approval of exactly the grants it requests.
    ApprovalRequired,
    /// A proxy host, an app operation or a provider dependency still needs the installation.
    DependencyBlocked,
    Unavailable,
    CatalogUnavailable,
    PackageSourceUnavailable,
    NetworkUnavailable,
    IncompatibleData,
    OperationFailed,
}

impl LifecycleFailure {
    fn outage(error: &io::Error) -> Option<Self> {
        Some(match unreachable_source(error)? {
            Source::Catalog => Self::CatalogUnavailable,
            Source::Package => Self::PackageSourceUnavailable,
            Source::Network => Self::NetworkUnavailable,
        })
    }
}

#[derive(Clone, Copy, Serialize)]
#[serde(tag = "status", rename_all = "camelCase")]
enum LifecycleStatus {
    Pending,
    Succeeded,
    Failed { error: LifecycleFailure },
}

#[derive(Clone, Serialize)]
pub(super) struct Lifecycle {
    #[serde(flatten)]
    request: lifecycle::Request,
    #[serde(flatten)]
    status: LifecycleStatus,
}

#[derive(Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
enum CatalogStatus {
    Loading,
    Ready,
    Stale,
    Unavailable,
}

#[derive(Serialize)]
struct View<'a> {
    state: CatalogStatus,
    entries: &'a [CatalogEntry],
    install: Option<Install>,
    installations: Vec<lifecycle::Installation>,
    lifecycle: Option<Lifecycle>,
}

struct State {
    status: CatalogStatus,
    entries: Option<Arc<[CatalogEntry]>>,
    install: Option<Install>,
    installations: Arc<[lifecycle::Installation]>,
    lifecycle: Option<Lifecycle>,
    next_refresh: Option<Instant>,
}

impl State {
    fn installing(&self) -> bool {
        self.install
            .as_ref()
            .is_some_and(|install| matches!(install.status, InstallStatus::Installing))
    }

    fn lifecycle_pending(&self) -> Option<&Lifecycle> {
        self.lifecycle
            .as_ref()
            .filter(|operation| matches!(operation.status, LifecycleStatus::Pending))
    }
}

#[derive(Clone)]
pub(super) struct Endpoint {
    config: Option<PathBuf>,
    state: Arc<Mutex<State>>,
    requests: mpsc::Sender<Request>,
}

impl Endpoint {
    pub(super) fn new(config: Option<PathBuf>) -> (Self, mpsc::Receiver<Request>) {
        let (requests, receiver) = mpsc::channel(1);
        let state = State {
            status: CatalogStatus::Loading,
            entries: None,
            install: None,
            installations: Arc::from([]),
            lifecycle: None,
            next_refresh: Some(Instant::now()),
        };
        (
            Self {
                config,
                state: Arc::new(Mutex::new(state)),
                requests,
            },
            receiver,
        )
    }

    fn state(&self) -> io::Result<MutexGuard<'_, State>> {
        self.state
            .lock()
            .map_err(|_| io::Error::other("Application catalog state unavailable"))
    }

    pub(super) fn view(&self) -> io::Result<Vec<u8>> {
        self.refresh()?;
        let (status, entries, install, installations, lifecycle) = {
            let state = self.state()?;
            (
                state.status,
                state.entries.clone(),
                state.install.clone(),
                Arc::clone(&state.installations),
                state.lifecycle.clone(),
            )
        };
        let entries = entries.as_deref().unwrap_or_default();
        let mut installations = installations.to_vec();
        for installation in &mut installations {
            // A stale listing is still signed; only update offers need a fresh one.
            installation.set_providers(entries);
            installation.set_listed_name(entries);
            if status == CatalogStatus::Ready {
                installation.set_update(entries);
            }
        }
        Ok(serde_json::to_vec(&View {
            state: status,
            entries,
            install,
            installations,
            lifecycle,
        })?)
    }

    /// Check the published installations against a target platform release. This blocks on the
    /// accepted catalog, so callers run it off the async executor.
    pub(super) fn check_target(&self, environment: &TargetEnvironment) -> io::Result<Vec<u8>> {
        #[derive(Serialize)]
        struct TargetView<'a> {
            installations: Vec<lifecycle::TargetInstallation<'a>>,
        }

        let published = Arc::clone(&self.state()?.installations);
        let installer = Installer::open_appliance(self.config.as_deref())?;
        let installations = lifecycle::check_target(&published, |releases| {
            installer.check_target(environment, releases)
        })?;
        Ok(serde_json::to_vec(&TargetView { installations })?)
    }

    pub(super) fn publish(&self, installations: Vec<lifecycle::Installation>) -> io::Result<()> {
        self.state()?.installations = installations.into();
        Ok(())
    }

    pub(super) fn refresh(&self) -> io::Result<()> {
        let load_checkpoint = {
            let mut state = self.state()?;
            if state.next_refresh.is_none_or(|next| next > Instant::now())
                || state.installing()
                || state.lifecycle_pending().is_some()
            {
                return Ok(());
            }
            state.next_refresh = None;
            state.status = CatalogStatus::Loading;
            state.entries.is_none()
        };
        let endpoint = self.clone();
        if let Err(error) = std::thread::Builder::new()
            .name("app-catalog-refresh".into())
            .spawn(move || {
                let entries = endpoint.load_catalog(load_checkpoint);
                if let Err(error) = endpoint.finish_refresh(entries) {
                    eprintln!("Application catalog state unavailable: {error}");
                }
            })
        {
            self.finish_refresh(Err(error))?;
        }
        Ok(())
    }

    fn load_catalog(&self, load_checkpoint: bool) -> io::Result<Vec<CatalogEntry>> {
        let installer = Installer::open_appliance(self.config.as_deref())?;
        if load_checkpoint && let Some(entries) = installer.browse_cached()? {
            self.state()?.entries = Some(entries.into());
        }
        installer.browse_latest()
    }

    fn finish_refresh(&self, entries: io::Result<Vec<CatalogEntry>>) -> io::Result<()> {
        let mut state = self.state()?;
        state.next_refresh = Some(Instant::now() + REFRESH_INTERVAL);
        state.status = match entries {
            Ok(entries) => {
                state.entries = Some(entries.into());
                CatalogStatus::Ready
            }
            Err(error) => {
                eprintln!("Could not refresh the application catalog: {error}");
                if state.entries.is_some() {
                    CatalogStatus::Stale
                } else {
                    CatalogStatus::Unavailable
                }
            }
        };
        Ok(())
    }

    pub(super) fn submit(&self, selection: Selection) -> Result<Install, Failure> {
        let mut state = self.state().map_err(|_| Failure::Unavailable)?;
        if state.lifecycle_pending().is_some() {
            return Err(Failure::Conflict);
        }
        if let Some(current) = &state.install
            && matches!(current.status, InstallStatus::Installing)
        {
            return if current.selection == selection {
                Ok(current.clone())
            } else {
                Err(Failure::Conflict)
            };
        }
        let entries = state.entries.as_deref().ok_or(Failure::Unavailable)?;
        let entry = entries
            .iter()
            .find(|entry| {
                entry.is_available()
                    && entry.app_id == selection.app_id
                    && entry.version == selection.version
                    && entry.archive_sha256 == selection.archive_sha256
            })
            .ok_or(Failure::Conflict)?;
        // A quick check against the signed listing. Staging decides again from fresh metadata.
        grants::decide(
            &entry.grants,
            &entry.permission_keys,
            selection.approval.as_deref().unwrap_or_default(),
            &selection.installation_id(),
        )
        .map_err(|_| Failure::ApprovalRequired)?;
        self.requests
            .try_send(Request::Install(selection.clone()))
            .map_err(|_| Failure::Unavailable)?;
        let install = Install {
            selection,
            status: InstallStatus::Installing,
        };
        state.install = Some(install.clone());
        Ok(install)
    }

    pub(super) fn finish(
        &self,
        selection: Selection,
        result: io::Result<String>,
    ) -> io::Result<()> {
        let status = match result {
            Ok(installation_id) => InstallStatus::Installed { installation_id },
            Err(error) => {
                eprintln!("Catalog application installation failed: {error}");
                InstallStatus::Failed {
                    error: match (unreachable_source(&error), error.kind()) {
                        _ if grants::approval_required(&error) => Failure::ApprovalRequired,
                        (Some(Source::Catalog), _) => Failure::CatalogUnavailable,
                        (Some(Source::Package), _) => Failure::PackageSourceUnavailable,
                        (Some(Source::Network), _) => Failure::NetworkUnavailable,
                        (None, io::ErrorKind::AlreadyExists) => Failure::Conflict,
                        (None, io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                            Failure::Unavailable
                        }
                        (None, _) => Failure::InstallFailed,
                    },
                }
            }
        };
        self.state()?.install = Some(Install { selection, status });
        Ok(())
    }

    pub(super) fn submit_lifecycle(
        &self,
        request: lifecycle::Request,
    ) -> Result<Lifecycle, Failure> {
        let mut state = self.state().map_err(|_| Failure::Unavailable)?;
        if let Some(current) = state.lifecycle_pending() {
            return if current.request == request {
                Ok(current.clone())
            } else {
                Err(Failure::Conflict)
            };
        }
        if state.installing() {
            return Err(Failure::Conflict);
        }
        let mut current = state
            .installations
            .iter()
            .find(|installation| installation.id() == request.installation_id)
            .cloned()
            .ok_or(Failure::Conflict)?;
        let entries = if state.status == CatalogStatus::Ready {
            state.entries.as_deref().unwrap_or_default()
        } else {
            &[]
        };
        current.set_update(entries);
        if !current.offers(&request, entries) {
            return Err(Failure::Conflict);
        }
        // A quick check against the signed listing. Staging decides again from fresh metadata.
        if !current.approves(&request, entries) {
            return Err(Failure::ApprovalRequired);
        }
        self.requests
            .try_send(Request::Lifecycle(request.clone()))
            .map_err(|_| Failure::Unavailable)?;
        let operation = Lifecycle {
            request,
            status: LifecycleStatus::Pending,
        };
        state.lifecycle = Some(operation.clone());
        Ok(operation)
    }

    pub(super) fn finish_lifecycle(
        &self,
        request: lifecycle::Request,
        result: io::Result<()>,
    ) -> io::Result<()> {
        let status = match result {
            Ok(()) => LifecycleStatus::Succeeded,
            Err(error) => {
                eprintln!(
                    "Application lifecycle operation failed for {}: {error}",
                    request.installation_id
                );
                let error = if lifecycle::incompatible(&error) {
                    LifecycleFailure::IncompatibleData
                } else if grants::approval_required(&error) {
                    LifecycleFailure::ApprovalRequired
                } else if let Some(outage) = LifecycleFailure::outage(&error) {
                    outage
                } else {
                    match error.kind() {
                        io::ErrorKind::AlreadyExists => LifecycleFailure::Conflict,
                        io::ErrorKind::ResourceBusy => LifecycleFailure::DependencyBlocked,
                        io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::ConnectionRefused => LifecycleFailure::Unavailable,
                        _ => LifecycleFailure::OperationFailed,
                    }
                };
                LifecycleStatus::Failed { error }
            }
        };
        self.state()?.lifecycle = Some(Lifecycle { request, status });
        Ok(())
    }
}

impl Manager {
    pub(super) async fn install_catalog(&mut self, selection: &Selection) -> io::Result<String> {
        let mut installation_id = selection.installation_id();
        let conflict = || {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Existing application requires explicit lifecycle management",
            )
        };
        let mut matches = self
            .journal
            .slots()
            .iter()
            .filter(|(_, slot)| slot.app_id == selection.app_id);
        if let Some((id, slot)) = matches.next() {
            if matches.next().is_some() {
                return Err(conflict());
            }
            match slot.removal {
                Removal::Removed if slot.removed_release.is_none() => {
                    installation_id.clone_from(id)
                }
                Removal::Purged => installation_id.clone_from(id),
                Removal::Installed => {
                    if slot
                        .active
                        .as_ref()
                        .is_some_and(|release| selection.matches(release))
                        && !slot.recovery_required
                        && let Some(live) = self.running.get_mut(id)
                        && !live.exited()?
                    {
                        return Ok(id.to_owned());
                    }
                    if id != &installation_id
                        || slot.active.is_some()
                        || slot
                            .candidate
                            .as_ref()
                            .is_some_and(|release| !selection.matches(release))
                    {
                        return Err(conflict());
                    }
                }
                Removal::Removed | Removal::Removing | Removal::Purging => return Err(conflict()),
            }
        } else if self.journal.slots().contains_key(&installation_id) {
            return Err(conflict());
        }
        self.admit_request(
            Command::Stage {
                installation_id: installation_id.clone(),
                app_id: selection.app_id.clone(),
                version: selection.version.clone(),
            },
            None,
            true,
        )?;
        // A new installation receives exactly the Owner's approval. Nothing is carried over.
        let gate = gate(
            installation_id.clone(),
            selection.approval.clone(),
            Vec::new(),
        );
        let download = Self::package(
            self.config.clone(),
            selection.app_id.clone(),
            selection.version.clone(),
            PackageRequest::Selected(selection.archive_sha256.clone(), Arc::clone(&gate)),
        );
        self.stage(
            &installation_id,
            selection.app_id.clone(),
            selection.version.clone(),
            download,
            Some(gate),
        )
        .await?;
        self.activate_catalog(&installation_id).await?;
        Ok(installation_id)
    }

    /// Activate the staged candidate with the approval that staging recorded for it.
    pub(super) async fn activate_catalog(&mut self, id: &str) -> io::Result<()> {
        self.settle_exit(id).await?;
        let slot = self.journal.slot(id)?;
        let candidate = slot
            .candidate
            .clone()
            .ok_or_else(|| super::bad("No staged catalog candidate"))?;
        if slot.removal == Removal::Purged {
            // The new generation may claim fresh storage before activation finishes.
            // Keep that claim recoverable, with the same UID and generation history.
            let mut slot = slot.clone();
            slot.removal = Removal::Removed;
            slot.removed_release = Some((&candidate).into());
            slot.removed_data_required = Some(false);
            self.journal.save(id, slot)?;
        }
        // Catalog staging records the candidate's approval. A release without one gets no grants.
        self.switch(id, candidate, Some(&[]), super::DataPolicy::Migrate)
            .await
    }
}
