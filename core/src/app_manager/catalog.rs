use std::{
    io,
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use marketplace_artifacts::digest;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use super::{Command, Manager, PackageRequest, journal::Release, journal::Removal};
use crate::app_install::{CatalogEntry, Installer};

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
}

impl Selection {
    fn matches(&self, release: &Release) -> bool {
        release.version == self.version && release.archive_sha256 == self.archive_sha256
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) enum Failure {
    Conflict,
    Unavailable,
    InstallFailed,
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
}

struct State {
    status: CatalogStatus,
    entries: Option<Arc<[CatalogEntry]>>,
    install: Option<Install>,
    next_refresh: Option<Instant>,
}

#[derive(Clone)]
pub(super) struct Endpoint {
    config: Option<PathBuf>,
    state: Arc<Mutex<State>>,
    requests: mpsc::Sender<Selection>,
}

impl Endpoint {
    pub(super) fn new(config: Option<PathBuf>) -> (Self, mpsc::Receiver<Selection>) {
        let (requests, receiver) = mpsc::channel(1);
        let state = State {
            status: CatalogStatus::Loading,
            entries: None,
            install: None,
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
        let (status, entries, install) = {
            let state = self.state()?;
            (state.status, state.entries.clone(), state.install.clone())
        };
        Ok(serde_json::to_vec(&View {
            state: status,
            entries: entries.as_deref().unwrap_or_default(),
            install,
        })?)
    }

    pub(super) fn refresh(&self) -> io::Result<()> {
        let load_checkpoint = {
            let mut state = self.state()?;
            if state.next_refresh.is_none_or(|next| next > Instant::now())
                || state
                    .install
                    .as_ref()
                    .is_some_and(|install| matches!(install.status, InstallStatus::Installing))
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
        if !entries.iter().any(|entry| {
            entry.is_available()
                && entry.app_id == selection.app_id
                && entry.version == selection.version
                && entry.archive_sha256 == selection.archive_sha256
        }) {
            return Err(Failure::Conflict);
        }
        self.requests
            .try_send(selection.clone())
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
                    error: match error.kind() {
                        io::ErrorKind::AlreadyExists => Failure::Conflict,
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => Failure::Unavailable,
                        _ => Failure::InstallFailed,
                    },
                }
            }
        };
        self.state()?.install = Some(Install { selection, status });
        Ok(())
    }
}

impl Manager {
    pub(super) async fn install_catalog(&mut self, selection: &Selection) -> io::Result<String> {
        let installation_id = format!("app-{}", &digest(selection.app_id.as_bytes())[..32]);
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
            if matches.next().is_some() || slot.removal != Removal::Installed {
                return Err(conflict());
            }
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
        let download = Self::package(
            self.config.clone(),
            selection.app_id.clone(),
            selection.version.clone(),
            PackageRequest::Selected(selection.archive_sha256.clone()),
        );
        self.stage(
            &installation_id,
            selection.app_id.clone(),
            selection.version.clone(),
            download,
        )
        .await?;
        self.execute(Command::Activate {
            installation_id: installation_id.clone(),
            grants: Vec::new(),
        })
        .await?;
        Ok(installation_id)
    }
}
