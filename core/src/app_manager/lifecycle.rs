use std::{fmt, io};

use semver::Version;
use serde::{Deserialize, Serialize};

use super::{
    Command, MAX_GENERATION, Manager, PackageRequest,
    journal::{ReleaseSelection, Removal, Slot},
    valid_id,
};
use crate::app_install::{CatalogEntry, InstalledRelease, TargetCheck};

#[cfg(test)]
#[path = "../../tests/private/app_manager/catalog_lifecycle.rs"]
mod tests;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
enum Action {
    Update,
    Deactivate,
    Reactivate,
    Uninstall,
    Recover,
    Rollback,
    Reinstall,
    Purge,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Expected {
    generation: u64,
    version: String,
    archive_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Request {
    action: Action,
    pub installation_id: String,
    expected: Expected,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<ReleaseSelection>,
}

impl Request {
    pub(super) fn valid(&self) -> bool {
        valid_id(&self.installation_id)
            && (1..=MAX_GENERATION).contains(&self.expected.generation)
            && valid_release(&self.expected.version, &self.expected.archive_sha256)
            && match (&self.action, &self.target) {
                (Action::Update | Action::Rollback | Action::Reinstall, Some(target)) => {
                    valid_release(&target.version, &target.archive_sha256)
                }
                (Action::Update | Action::Rollback | Action::Reinstall, None) | (_, Some(_)) => {
                    false
                }
                (_, None) => true,
            }
    }
}

fn valid_release(version: &str, digest: &str) -> bool {
    version.len() <= 64
        && version.parse::<Version>().is_ok_and(|version| {
            version.build.is_empty()
                && [version.major, version.minor, version.patch]
                    .into_iter()
                    .all(|component| component <= 999_999)
        })
        && digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
enum InstallationState {
    Running,
    Disabled,
    RecoveryRequired,
    Removing,
    Removed,
    Purging,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Installation {
    installation_id: String,
    app_id: String,
    generation: u64,
    #[serde(flatten)]
    release: ReleaseSelection,
    state: InstallationState,
    /// Provider profiles of this exact release in the catalog listing; absent if it is unlisted.
    providers: Option<Vec<String>>,
    update: Option<ReleaseSelection>,
    previous: Option<ReleaseSelection>,
}

/// One installation checked against a target platform release.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct TargetInstallation<'a> {
    installation_id: &'a str,
    app_id: &'a str,
    #[serde(flatten)]
    release: &'a ReleaseSelection,
    state: InstallationState,
    #[serde(flatten)]
    check: TargetCheck,
}

/// Check every installation the platform may start again; removed releases never start.
/// `check` answers for each release in order, normally `Installer::check_target`.
pub(super) fn check_target<'a>(
    installations: &'a [Installation],
    check: impl FnOnce(&[InstalledRelease<'_>]) -> io::Result<Vec<TargetCheck>>,
) -> io::Result<Vec<TargetInstallation<'a>>> {
    use InstallationState as State;

    let installed: Vec<_> = installations
        .iter()
        .filter(|row| {
            matches!(
                row.state,
                State::Running | State::Disabled | State::RecoveryRequired
            )
        })
        .collect();
    let releases: Vec<_> = installed
        .iter()
        .map(|row| InstalledRelease {
            app_id: &row.app_id,
            version: &row.release.version,
            archive_sha256: &row.release.archive_sha256,
        })
        .collect();
    let checks = check(&releases)?;
    if checks.len() != installed.len() {
        return Err(io::Error::other("Target check result is incomplete"));
    }
    Ok(installed
        .into_iter()
        .zip(checks)
        .map(|(row, check)| TargetInstallation {
            installation_id: &row.installation_id,
            app_id: &row.app_id,
            release: &row.release,
            state: row.state,
            check,
        })
        .collect())
}

impl Installation {
    fn new(id: &str, slot: &Slot, running: bool) -> Option<Self> {
        use InstallationState as State;

        if slot.generation == 0 {
            return None;
        }
        let state = match slot.removal {
            Removal::Installed if slot.desired_running && running && !slot.recovery_required => {
                State::Running
            }
            Removal::Installed
                if slot.desired_running || slot.pending_fence || slot.recovery_required =>
            {
                State::RecoveryRequired
            }
            Removal::Installed => State::Disabled,
            Removal::Removing => State::Removing,
            Removal::Removed => State::Removed,
            Removal::Purging => State::Purging,
            Removal::Purged => return None,
        };
        let release = match state {
            State::Removed | State::Purging => slot.removed_release.clone()?,
            _ => slot.active.as_ref()?.into(),
        };
        Some(Self {
            installation_id: id.to_owned(),
            app_id: slot.app_id.clone(),
            generation: slot.generation,
            release,
            state,
            providers: None,
            update: None,
            previous: slot.previous.as_ref().map(Into::into),
        })
    }

    pub(super) fn id(&self) -> &str {
        &self.installation_id
    }

    /// Copy the provider profiles of the exact installed release from the signed listing.
    pub(super) fn set_providers(&mut self, entries: &[CatalogEntry]) {
        self.providers = entries
            .iter()
            .find(|entry| {
                entry.app_id == self.app_id
                    && entry.version == self.release.version
                    && entry.archive_sha256 == self.release.archive_sha256
            })
            .map(|entry| entry.providers.clone());
    }

    pub(super) fn set_update(&mut self, entries: &[CatalogEntry]) {
        if self.state != InstallationState::Running {
            return;
        }
        let Ok(active) = self.release.version.parse::<Version>() else {
            return;
        };
        self.update = entries
            .iter()
            .filter(|entry| entry.app_id == self.app_id && entry.is_available())
            .filter_map(|entry| {
                let version = entry.version.parse::<Version>().ok()?;
                version
                    .cmp_precedence(&active)
                    .is_gt()
                    .then_some((version, entry))
            })
            .max_by(|(first, _), (second, _)| first.cmp_precedence(second))
            .map(|(_, entry)| ReleaseSelection {
                version: entry.version.clone(),
                archive_sha256: entry.archive_sha256.clone(),
            });
    }

    pub(super) fn permits(&self, request: &Request) -> bool {
        use InstallationState as State;

        self.generation == request.expected.generation
            && self.release.version == request.expected.version
            && self.release.archive_sha256 == request.expected.archive_sha256
            && match request.action {
                Action::Update => {
                    self.state == State::Running
                        && request.target.as_ref().is_some_and(|target| {
                            strictly_newer(&target.version, &self.release.version)
                        })
                }
                Action::Deactivate => matches!(
                    self.state,
                    State::Running | State::Disabled | State::RecoveryRequired
                ),
                Action::Reactivate => self.state == State::Disabled,
                Action::Uninstall => matches!(
                    self.state,
                    State::Running | State::Disabled | State::RecoveryRequired | State::Removing
                ),
                Action::Recover => self.state == State::RecoveryRequired,
                Action::Rollback => {
                    matches!(self.state, State::Running | State::RecoveryRequired)
                        && self
                            .previous
                            .as_ref()
                            .is_some_and(|previous| request.target.as_ref() == Some(previous))
                }
                Action::Reinstall => self.state == State::Removed && request.target.is_some(),
                Action::Purge => matches!(self.state, State::Removed | State::Purging),
            }
    }

    pub(super) fn offers(&self, request: &Request, entries: &[CatalogEntry]) -> bool {
        self.permits(request)
            && match request.action {
                Action::Update => self.update.as_ref() == request.target.as_ref(),
                Action::Reinstall => request.target.as_ref().is_some_and(|target| {
                    entries.iter().any(|entry| {
                        entry.is_available()
                            && entry.app_id == self.app_id
                            && entry.version == target.version
                            && entry.archive_sha256 == target.archive_sha256
                    })
                }),
                _ => true,
            }
    }
}

fn strictly_newer(target: &str, active: &str) -> bool {
    match (target.parse::<Version>(), active.parse::<Version>()) {
        (Ok(target), Ok(active)) => target.cmp_precedence(&active).is_gt(),
        _ => false,
    }
}

#[derive(Debug)]
pub(super) struct IncompatibleData;

impl fmt::Display for IncompatibleData {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Declared data versions require migration or recovery")
    }
}

impl std::error::Error for IncompatibleData {}

pub(super) fn incompatible(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|cause| cause.is::<IncompatibleData>())
}

fn conflict() -> io::Error {
    io::Error::new(
        io::ErrorKind::AlreadyExists,
        "Installation lifecycle precondition changed",
    )
}

impl Manager {
    pub(super) fn local_installations(&self) -> Vec<Installation> {
        self.journal
            .slots()
            .iter()
            .filter_map(|(id, slot)| Installation::new(id, slot, self.running.contains_key(id)))
            .collect()
    }

    pub(super) async fn manage_lifecycle(&mut self, request: &Request) -> io::Result<()> {
        let id = &request.installation_id;
        let command = match request.action {
            Action::Update | Action::Reinstall => Command::Activate {
                installation_id: id.clone(),
                grants: Vec::new(),
            },
            Action::Deactivate => Command::Stop {
                installation_id: id.clone(),
            },
            Action::Reactivate | Action::Recover => Command::Start {
                installation_id: id.clone(),
            },
            Action::Uninstall => Command::Remove {
                installation_id: id.clone(),
            },
            Action::Rollback => Command::Rollback {
                installation_id: id.clone(),
            },
            Action::Purge => Command::Purge {
                installation_id: id.clone(),
            },
        };
        let command = self.admit_request(command, None, true)?;
        self.check_exits(None)?;
        let current = self.lifecycle_installation(request)?;
        if request.action == Action::Deactivate && current.state == InstallationState::Disabled {
            return Ok(());
        }
        if matches!(request.action, Action::Update | Action::Reinstall) {
            let target = request.target.as_ref().ok_or_else(conflict)?;
            let app = current.app_id;
            let download = Self::package(
                self.config.clone(),
                app.clone(),
                target.version.clone(),
                PackageRequest::Selected(target.archive_sha256.clone()),
            );
            self.stage(id, app, target.version.clone(), download)
                .await?;
            self.check_exits(None)?;
            self.lifecycle_installation(request)?;
            let grants = (request.action == Action::Reinstall).then_some([].as_slice());
            return self.activate_catalog(id, grants).await;
        }
        self.execute(command).await?;
        Ok(())
    }

    fn lifecycle_installation(&self, request: &Request) -> io::Result<Installation> {
        let id = &request.installation_id;
        let slot = self.journal.slot(id).map_err(|_| conflict())?;
        Installation::new(id, slot, self.running.contains_key(id))
            .filter(|current| current.permits(request))
            .ok_or_else(conflict)
    }
}
