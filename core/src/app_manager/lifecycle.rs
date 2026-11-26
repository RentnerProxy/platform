use std::{collections::BTreeSet, fmt, io, sync::Arc};

use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{
    Command, MAX_GENERATION, Manager, PackageRequest, gate,
    gateway::identity,
    journal::{Grant, ReleaseSelection, Removal, Slot},
    valid_id,
};
use crate::app_install::{
    CatalogEntry, InstalledRelease, TargetCheck,
    grants::{self, ApprovedGrant, Capability, MAX_GRANTS},
};

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
    /// Withdraw approved grants from the installation without a restart.
    Revoke,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Expected {
    generation: u64,
    version: String,
    archive_sha256: String,
}

/// One approved grant the Owner revokes.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct RevokedGrant {
    capability: Capability,
    resource_id: String,
}

impl RevokedGrant {
    fn names(&self, grant: &Grant) -> bool {
        grant.capability == self.capability && grant.resource_id == self.resource_id
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Request {
    action: Action,
    pub installation_id: String,
    expected: Expected,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<ReleaseSelection>,
    /// The Owner's approval for an update or reinstall. Receipts never repeat it.
    #[serde(default, skip_serializing)]
    approval: Option<Vec<ApprovedGrant>>,
    /// The grants a revocation withdraws. Receipts never repeat them.
    #[serde(default, skip_serializing)]
    grants: Option<Vec<RevokedGrant>>,
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
            && match (&self.action, &self.approval) {
                (Action::Update | Action::Reinstall, Some(approval)) => {
                    approval.len() <= MAX_GRANTS
                }
                (_, Some(_)) => false,
                (_, None) => true,
            }
            && match (&self.action, &self.grants) {
                (Action::Revoke, Some(grants)) => {
                    (1..=MAX_GRANTS).contains(&grants.len())
                        && grants.iter().collect::<BTreeSet<_>>().len() == grants.len()
                }
                (Action::Revoke, None) | (_, Some(_)) => false,
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
    /// Display name from the verified manifest of this exact release, when the running
    /// generation loaded it or the signed listing still names it.
    name: Option<String>,
    /// Provider profiles of this exact release in the catalog listing; absent if it is unlisted.
    providers: Option<Vec<String>>,
    /// The grants approved for this exact release; absent if it predates recorded approvals.
    grants: Option<Vec<Grant>>,
    update: Option<ReleaseSelection>,
    /// Whether the offered update requests grants that the current approval does not cover.
    update_requires_approval: bool,
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
        let (release, grants) = match state {
            State::Removed | State::Purging => {
                let removed = slot.removed_release.clone()?;
                // A removed release has no manifest digest. Reinstalling decides again from
                // the target's signed manifest.
                let grants = slot
                    .approvals
                    .get(&removed.archive_sha256)
                    .map(|approval| approval.grants.clone());
                (removed, grants)
            }
            _ => {
                let active = slot.active.as_ref()?;
                let grants = slot.approval_for(active).ok().flatten().map(<[_]>::to_vec);
                (active.into(), grants)
            }
        };
        Some(Self {
            installation_id: id.to_owned(),
            app_id: slot.app_id.clone(),
            generation: slot.generation,
            release,
            state,
            name: None,
            providers: None,
            grants,
            update: None,
            update_requires_approval: false,
            previous: slot.previous.as_ref().map(Into::into),
        })
    }

    /// Whether `entry` needs a new approval, after carrying this installation's approved
    /// grants. A release approved before approvals were recorded carries none.
    fn requires_approval(&self, entry: &CatalogEntry) -> bool {
        grants::carry(
            self.grants.as_deref().unwrap_or_default(),
            &entry.grants,
            &entry.permission_keys,
            &self.installation_id,
        )
        .is_none()
    }

    /// The listed entry of `target` for this app.
    fn listed<'a>(
        &self,
        target: &ReleaseSelection,
        entries: &'a [CatalogEntry],
    ) -> Option<&'a CatalogEntry> {
        entries.iter().find(|entry| {
            entry.is_available()
                && entry.app_id == self.app_id
                && entry.version == target.version
                && entry.archive_sha256 == target.archive_sha256
        })
    }

    pub(super) fn id(&self) -> &str {
        &self.installation_id
    }

    /// Keep the display name of the manifest that the running generation verified and loaded.
    pub(super) fn with_name(mut self, name: Option<String>) -> Self {
        self.name = name;
        self
    }

    /// Without a loaded manifest, take the display name of the exact release from the signed
    /// listing. Its manifest digest is bound to the same archive.
    pub(super) fn set_listed_name(&mut self, entries: &[CatalogEntry]) {
        if self.name.is_some() {
            return;
        }
        self.name = entries
            .iter()
            .find(|entry| {
                entry.app_id == self.app_id
                    && entry.version == self.release.version
                    && entry.archive_sha256 == self.release.archive_sha256
            })
            .map(|entry| entry.name.clone());
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
        let offered = entries
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
            .map(|(_, entry)| entry);
        self.update_requires_approval = offered.is_some_and(|entry| self.requires_approval(entry));
        self.update = offered.map(|entry| ReleaseSelection {
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
                Action::Revoke => {
                    matches!(
                        self.state,
                        State::Running | State::Disabled | State::RecoveryRequired
                    ) && request.grants.as_ref().is_some_and(|revoked| {
                        revoked.iter().all(|revoked| {
                            self.grants
                                .iter()
                                .flatten()
                                .any(|grant| revoked.names(grant))
                        })
                    })
                }
            }
    }

    pub(super) fn offers(&self, request: &Request, entries: &[CatalogEntry]) -> bool {
        self.permits(request)
            && match request.action {
                Action::Update => self.update.as_ref() == request.target.as_ref(),
                Action::Reinstall => request
                    .target
                    .as_ref()
                    .is_some_and(|target| self.listed(target, entries).is_some()),
                _ => true,
            }
    }

    /// Whether the listed target of an offered update or reinstall receives an approval: the
    /// request's own, which must match the target exactly, or the carried one.
    pub(super) fn approves(&self, request: &Request, entries: &[CatalogEntry]) -> bool {
        if !matches!(request.action, Action::Update | Action::Reinstall) {
            return true;
        }
        let Some(entry) = request
            .target
            .as_ref()
            .and_then(|target| self.listed(target, entries))
        else {
            return false;
        };
        match &request.approval {
            Some(approval) => grants::decide(
                &entry.grants,
                &entry.permission_keys,
                approval,
                &self.installation_id,
            )
            .is_ok(),
            None => !self.requires_approval(entry),
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
            .filter_map(|(id, slot)| {
                let live = self.running.get(id);
                Installation::new(id, slot, live.is_some())
                    .map(|row| row.with_name(live.and_then(|live| live.name.clone())))
            })
            .collect()
    }

    pub(super) async fn manage_lifecycle(&mut self, request: &Request) -> io::Result<()> {
        let id = &request.installation_id;
        let command = match request.action {
            // Admission only: these actions run their own steps below.
            Action::Update | Action::Reinstall | Action::Revoke => Command::Activate {
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
        if request.action == Action::Revoke {
            return self
                .revoke(id, request.grants.as_deref().unwrap_or_default())
                .await;
        }
        if matches!(request.action, Action::Update | Action::Reinstall) {
            let target = request.target.as_ref().ok_or_else(conflict)?;
            let app = current.app_id;
            // Without the Owner's approval, an update carries the running release's approval
            // and a reinstall the removed release's, if it still covers the target. A release
            // approved before approvals were recorded carries none.
            let slot = self.journal.slot(id)?;
            let carried = match request.action {
                Action::Update => slot
                    .active
                    .as_ref()
                    .and_then(|active| slot.approval_for(active).ok().flatten()),
                _ => slot
                    .removed_release
                    .as_ref()
                    .and_then(|removed| slot.approvals.get(&removed.archive_sha256))
                    .map(|approval| approval.grants.as_slice()),
            }
            .unwrap_or_default()
            .to_vec();
            let gate = gate(id.clone(), request.approval.clone(), carried);
            let download = Self::package(
                self.config.clone(),
                app.clone(),
                target.version.clone(),
                PackageRequest::Selected(target.archive_sha256.clone(), Arc::clone(&gate)),
            );
            self.stage(id, app, target.version.clone(), download, Some(gate))
                .await?;
            self.check_exits(None)?;
            self.lifecycle_installation(request)?;
            return self.activate_catalog(id).await;
        }
        self.execute(command).await?;
        Ok(())
    }

    /// Withdraw `revoked` from every stored approval, then from the live generation, so that its
    /// next call is refused. If the live generation cannot drop them, it is fenced: an app never
    /// keeps a grant that the Owner revoked. A crash before the publication leaves the boot to
    /// fence the generation and start it with the reduced approval.
    async fn revoke(&mut self, id: &str, revoked: &[RevokedGrant]) -> io::Result<()> {
        let mut slot = self.journal.slot(id)?.clone();
        slot.revoke(|grant| revoked.iter().any(|revoked| revoked.names(grant)));
        self.journal.save(id, slot)?;
        if !self.running.contains_key(id) {
            return Ok(());
        }
        let slot = self.journal.slot(id)?;
        let remaining = match &slot.active {
            Some(active) => slot
                .approval_for(active)
                .map(|approved| approved.unwrap_or_default().to_vec()),
            None => Ok(Vec::new()),
        };
        let published = match remaining {
            Ok(grants) => {
                let body = json!({"identity": identity(id, slot), "grants": grants});
                self.gateway.post("grants", body).await
            }
            Err(error) => Err(error),
        };
        if let Err(error) = published {
            let mut slot = self.journal.slot(id)?.clone();
            slot.require_recovery();
            self.journal.save(id, slot)?;
            self.fence(id).await?;
            return Err(error);
        }
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
