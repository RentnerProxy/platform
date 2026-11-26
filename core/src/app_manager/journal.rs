use super::{bad, valid_id};
use crate::app_install::grants::MAX_GRANTS;
pub(super) use crate::app_install::grants::{Capability, Grant};
use crate::app_ipc::filesystem::{lock_file, require_safe_parents};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Read},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    thread,
};
use tokio::{
    runtime::Handle,
    sync::oneshot,
    time::{Instant, timeout_at},
};

const MAX_BYTES: u64 = 4 * 1024 * 1024;
pub(super) const LIMIT: usize = 256;

/// The grants the Owner, or root with the control CLI, approved for one exact release.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Approval {
    pub manifest_sha256: String,
    pub grants: Vec<Grant>,
}

/// A stored approval that names another manifest than the release it would start.
#[derive(Debug)]
pub(super) struct ApprovalMismatch;

impl std::fmt::Display for ApprovalMismatch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Stored approval belongs to another release manifest")
    }
}

impl std::error::Error for ApprovalMismatch {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Release {
    pub version: String,
    pub archive_sha256: String,
    pub manifest_sha256: String,
    pub catalog_revision: u64,
}

impl Release {
    pub fn same_package(&self, other: &Self) -> bool {
        self.version == other.version
            && self.archive_sha256 == other.archive_sha256
            && self.manifest_sha256 == other.manifest_sha256
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ReleaseSelection {
    pub version: String,
    pub archive_sha256: String,
}

impl From<&Release> for ReleaseSelection {
    fn from(release: &Release) -> Self {
        Self {
            version: release.version.clone(),
            archive_sha256: release.archive_sha256.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Data {
    pub target_version: u32,
    pub read_versions: Vec<u32>,
    pub write_versions: Vec<u32>,
    pub migrations: Vec<serde_json::Value>,
}

impl Data {
    fn opens(&self, version: u32) -> bool {
        self.read_versions.contains(&version) && self.write_versions.contains(&version)
    }

    fn starts_fresh(&self) -> bool {
        self.migrations
            .iter()
            .any(|step| step["fromVersion"].as_f64() == Some(0.0))
    }

    /// Follow the declared forward steps from `version` to the target. The platform only runs SQL.
    fn migration_from(&self, version: u32) -> Option<Migration> {
        let mut current = version;
        let mut steps = Vec::new();
        while current < self.target_version {
            let step = self
                .migrations
                .iter()
                .find(|step| step["fromVersion"].as_f64() == Some(f64::from(current)))?;
            let next = step["toVersion"].as_f64().filter(|next| {
                next.fract() == 0.0
                    && *next > f64::from(current)
                    && *next <= f64::from(self.target_version)
            })? as u32;
            steps.push(
                step["path"]
                    .as_str()
                    .filter(|path| sql_step(path))?
                    .to_owned(),
            );
            current = next;
        }
        (!steps.is_empty()).then_some(Migration {
            from: version,
            to: current,
            steps,
        })
    }
}

/// A package-relative `migrations/**.sql` path in the contract's file name alphabet.
fn sql_step(path: &str) -> bool {
    path.strip_prefix("migrations/")
        .and_then(|path| path.strip_suffix(".sql"))
        .is_some_and(|path| {
            path.split('/').all(|segment| {
                segment.split('.').all(|part| {
                    !part.is_empty()
                        && part
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
                })
            })
        })
}

/// Whether `next` reads and writes every version the last release may have written.
fn keeps(written: &Data, next: &Data) -> bool {
    written.target_version == next.target_version
        && written.write_versions.iter().all(|v| next.opens(*v))
}

/// What activating a release does to the installation's durable data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum DataChange {
    Keep,
    Migrate(Migration),
}

/// Declared SQL steps that run in order inside one transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Migration {
    pub from: u32,
    pub to: u32,
    pub steps: Vec<String>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Slot {
    pub app_id: String,
    pub uid: u32,
    pub generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_recorded: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_claimed: Option<bool>,
    pub candidate: Option<Release>,
    pub active: Option<Release>,
    pub previous: Option<Release>,
    pub written: Option<Data>,
    pub desired_running: bool,
    pub pending_fence: bool,
    pub database_provisioned: bool,
    pub recovery_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grants_uncertain: Option<bool>,
    pub provider_dependencies_unknown: bool,
    pub removal: Removal,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed_release: Option<ReleaseSelection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed_data_required: Option<bool>,
    /// The release whose data migration may have committed before its activation finished.
    /// Only the platform records it, unlike the version marker inside the app's own database.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub migrating: Option<ReleaseSelection>,
    /// Approved grants by archive digest, for the releases this installation still references.
    /// A release without an entry predates recorded approvals.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub approvals: BTreeMap<String, Approval>,
}

impl Slot {
    /// The grants approved for exactly `release`, or `None` for a release approved before
    /// approvals were recorded. An approval for the same archive with another manifest refuses.
    pub fn approval_for(&self, release: &Release) -> io::Result<Option<&[Grant]>> {
        match self.approvals.get(&release.archive_sha256) {
            Some(approval) if approval.manifest_sha256 == release.manifest_sha256 => {
                Ok(Some(&approval.grants))
            }
            Some(_) => Err(io::Error::other(ApprovalMismatch)),
            None => Ok(None),
        }
    }

    /// Record `grants` as the approval of exactly `release`.
    pub fn approve(&mut self, release: &Release, grants: Vec<Grant>) {
        self.approvals.insert(
            release.archive_sha256.clone(),
            Approval {
                manifest_sha256: release.manifest_sha256.clone(),
                grants,
            },
        );
    }

    /// Remove every grant that `revoked` names from every stored approval, so that neither a
    /// restart, a rollback nor a reinstall can restore it.
    pub fn revoke(&mut self, revoked: impl Fn(&Grant) -> bool) {
        for approval in self.approvals.values_mut() {
            approval.grants.retain(|grant| !revoked(grant));
        }
    }

    /// Keep only the approvals of releases this installation can still start or reinstall.
    /// Every journal save applies it.
    pub fn prune_approvals(&mut self) {
        let referenced: BTreeSet<_> = [&self.active, &self.candidate, &self.previous]
            .into_iter()
            .flatten()
            .map(|release| release.archive_sha256.clone())
            .chain(
                self.removed_release
                    .as_ref()
                    .map(|release| release.archive_sha256.clone()),
            )
            .collect();
        self.approvals
            .retain(|archive_sha256, _| referenced.contains(archive_sha256));
    }

    pub fn uncertain_grants(&self) -> bool {
        // Older interrupted journals did not distinguish missing files from ambiguous activation.
        self.grants_uncertain.unwrap_or(self.recovery_required)
    }

    pub fn require_recovery(&mut self) {
        self.grants_uncertain = Some(self.uncertain_grants());
        self.recovery_required = true;
    }

    pub fn acknowledge_fence(&mut self) {
        self.pending_fence = false;
        self.authority_recorded = Some(true);
    }

    /// Decide how `release` opens the stored data, or `None` when it cannot. `recorded` is the
    /// schema version the last migration stored in the database. Without one, only the last
    /// release's declaration describes the data, and a package switch keeps the previous release
    /// able to read it unless a declared migration changes the data. Without `may_migrate`, the
    /// release must open the data as it is.
    pub fn plan(
        &self,
        release: &Release,
        next: Option<&Data>,
        recorded: Option<u32>,
        may_migrate: bool,
    ) -> Option<DataChange> {
        let Some(next) = next else {
            return (self.written.is_none() && recorded.is_none()).then_some(DataChange::Keep);
        };
        let switching = self
            .active
            .as_ref()
            .is_some_and(|active| !active.same_package(release));
        let migrate = |version| {
            may_migrate
                .then(|| next.migration_from(version))
                .flatten()
                .map(DataChange::Migrate)
        };
        match (recorded, &self.written) {
            (Some(version), _) => (version < next.target_version)
                .then(|| migrate(version))
                .flatten()
                .or_else(|| next.opens(version).then_some(DataChange::Keep)),
            (None, None) if next.starts_fresh() => migrate(0),
            // Data cannot appear under an existing installation without a declared migration.
            (None, None) => (!switching).then_some(DataChange::Keep),
            (None, Some(written)) if written.target_version < next.target_version => {
                migrate(written.target_version)
            }
            (None, Some(written)) => (keeps(written, next) && (!switching || keeps(next, written)))
                .then_some(DataChange::Keep),
        }
    }

    /// The staged release whose own activation started a data migration. Once its migration may
    /// have committed, recovery finishes that activation instead of reopening the old release.
    pub fn migrated_candidate(&self) -> Option<Release> {
        self.candidate
            .clone()
            .filter(|candidate| self.migrating.as_ref() == Some(&ReleaseSelection::from(candidate)))
    }

    pub fn commit_release(&mut self, release: Release) {
        if self
            .candidate
            .as_ref()
            .is_some_and(|candidate| candidate.same_package(&release))
        {
            self.candidate = None;
        }
        if self
            .active
            .as_ref()
            .is_some_and(|active| !active.same_package(&release))
        {
            self.previous = self.active.take();
        }
        self.active = Some(release);
        self.migrating = None;
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) enum Removal {
    #[default]
    Installed,
    Removing,
    Removed,
    Purging,
    Purged,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct State {
    format_version: u8,
    installations: BTreeMap<String, Slot>,
}

pub(super) struct Journal {
    directory: PathBuf,
    lock: File,
    state: Arc<State>,
    poisoned: bool,
}

pub(super) struct ShutdownCommit(Arc<State>);

pub(super) struct ShutdownWrite {
    deadline: Instant,
    receive: oneshot::Receiver<io::Result<ShutdownCommit>>,
}

impl ShutdownWrite {
    pub(super) async fn wait(&mut self) -> io::Result<ShutdownCommit> {
        timeout_at(self.deadline, &mut self.receive)
            .await?
            .map_err(io::Error::other)?
    }
}

pub(super) fn private_directory(path: &Path) -> io::Result<()> {
    require_safe_parents(path, 0)?;
    match DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => (),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e),
    }
    let m = fs::symlink_metadata(path)?;
    if !m.is_dir() || m.uid() != 0 || m.mode() & 0o7777 != 0o700 {
        return Err(bad("Unsafe manager directory"));
    }
    File::open(
        path.parent()
            .ok_or_else(|| bad("Missing directory parent"))?,
    )?
    .sync_all()
}

pub(super) fn lock(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let stat = file.metadata()?;
    if !stat.is_file() || stat.uid() != 0 || stat.nlink() != 1 || stat.mode() & 0o7777 != 0o600 {
        return Err(bad("Unsafe manager lock"));
    }
    lock_file(&file)?;
    Ok(file)
}

impl Journal {
    pub fn open(directory: &Path) -> io::Result<Self> {
        private_directory(directory)?;
        let guard = lock(&directory.join("manager.lock"))?;
        let mut state = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(directory.join("journal.json"))
        {
            Ok(file) => {
                let meta = file.metadata()?;
                if !meta.is_file()
                    || meta.uid() != 0
                    || meta.nlink() != 1
                    || meta.mode() & 0o7777 != 0o600
                    || meta.len() > MAX_BYTES
                {
                    return Err(bad("Unsafe manager journal"));
                }
                serde_json::from_reader(file.take(MAX_BYTES + 1))?
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => State {
                format_version: 1,
                installations: BTreeMap::new(),
            },
            Err(e) => return Err(e),
        };
        if state.format_version != 1 {
            return Err(bad("Invalid manager journal version"));
        }
        validate_installations(&state.installations)?;
        for slot in state.installations.values_mut() {
            slot.authority_recorded.get_or_insert(slot.generation > 0);
        }
        Ok(Self {
            directory: directory.to_owned(),
            lock: guard,
            state: Arc::new(state),
            poisoned: false,
        })
    }

    pub fn slots(&self) -> &BTreeMap<String, Slot> {
        &self.state.installations
    }
    pub fn slot(&self, id: &str) -> io::Result<&Slot> {
        self.slots()
            .get(id)
            .ok_or_else(|| bad("Unknown installation"))
    }
    pub fn writer(&self, uid: u32) -> io::Result<File> {
        lock(&self.writer_path(uid))
    }
    pub fn writer_path(&self, uid: u32) -> PathBuf {
        self.directory.join(format!("writer-{uid}.lock"))
    }
    pub fn writable(&self) -> io::Result<()> {
        if self.poisoned {
            return Err(bad("Restart required after journal I/O failure"));
        }
        Ok(())
    }
    pub fn save(&mut self, id: &str, mut slot: Slot) -> io::Result<()> {
        self.writable()?;
        slot.prune_approvals();
        let mut next = self.state.as_ref().clone();
        next.installations.insert(id.to_owned(), slot);
        let bytes = encode_state(&next)?;
        self.poisoned = true;
        persist_state(&self.directory, &bytes, || Ok(()))?;
        self.state = Arc::new(next);
        self.poisoned = false;
        Ok(())
    }

    pub(super) fn restore_installations(
        &mut self,
        installations: BTreeMap<String, Slot>,
    ) -> io::Result<()> {
        self.writable()?;
        if !self.slots().is_empty() {
            return Err(bad("Portable recovery requires an empty manager journal"));
        }
        validate_installations(&installations)?;
        self.replace_installations(installations)
    }

    /// Forgets every installation after a portable restore retired its storage and databases.
    pub(super) fn retire_installations(&mut self) -> io::Result<()> {
        self.writable()?;
        self.replace_installations(BTreeMap::new())
    }

    fn replace_installations(&mut self, installations: BTreeMap<String, Slot>) -> io::Result<()> {
        let next = State {
            format_version: 1,
            installations,
        };
        let bytes = encode_state(&next)?;
        self.poisoned = true;
        persist_state(&self.directory, &bytes, || Ok(()))?;
        self.state = Arc::new(next);
        self.poisoned = false;
        Ok(())
    }

    pub(super) fn begin_shutdown_save(
        &mut self,
        fenced: BTreeSet<String>,
        deadline: Instant,
    ) -> io::Result<ShutdownWrite> {
        self.writable()?;
        if fenced.is_empty() {
            return Err(bad("No shutdown fences to commit"));
        }
        check_write_deadline(deadline)?;
        let base = Arc::clone(&self.state);
        let directory = self.directory.clone();
        let lock = self.lock.try_clone()?;
        let runtime = Handle::current();
        let (send, receive) = oneshot::channel();
        // A stalled fsync must not hold Tokio's runtime open during shutdown.
        // Hold the journal lock and use the manager's clock until this writer exits.
        let worker = thread::Builder::new()
            .name("app-manager-journal".into())
            .spawn(move || {
                let _runtime = runtime.enter();
                let result = (|| {
                    let may_publish = || {
                        if send.is_closed() {
                            return Err(io::Error::new(
                                io::ErrorKind::Interrupted,
                                "Manager journal shutdown commit cancelled",
                            ));
                        }
                        check_write_deadline(deadline)
                    };
                    may_publish()?;
                    let mut next = base.as_ref().clone();
                    for id in fenced {
                        next.installations
                            .get_mut(&id)
                            .ok_or_else(|| bad("Unknown installation"))?
                            .acknowledge_fence();
                    }
                    let bytes = encode_state(&next)?;
                    persist_state(&directory, &bytes, may_publish)?;
                    Ok::<_, io::Error>(ShutdownCommit(Arc::new(next)))
                })();
                drop(lock);
                let _ = send.send(result);
            })?;
        drop(worker);
        self.poisoned = true;
        Ok(ShutdownWrite { deadline, receive })
    }

    pub(super) fn complete_shutdown_save(&mut self, commit: ShutdownCommit) {
        self.state = commit.0;
        self.poisoned = false;
    }
}

fn validate_installations(installations: &BTreeMap<String, Slot>) -> io::Result<()> {
    let mut uids = BTreeSet::new();
    if installations.len() > LIMIT
        || installations.iter().any(|(id, slot)| {
            !valid_id(id)
                || !(20_000..=59_999).contains(&slot.uid)
                || !uids.insert(slot.uid)
                || slot.generation > super::MAX_GENERATION
                || slot.pending_fence && slot.generation == 0
                || slot
                    .approvals
                    .values()
                    .any(|approval| approval.grants.len() > MAX_GRANTS)
        })
    {
        return Err(bad("Invalid manager journal"));
    }
    Ok(())
}

pub(super) fn validate_portable_inventory(
    installations: &BTreeMap<String, Slot>,
) -> io::Result<()> {
    validate_installations(installations)?;
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct StateRef<'a> {
        format_version: u8,
        installations: &'a BTreeMap<String, Slot>,
    }
    encode_state(&StateRef {
        format_version: 1,
        installations,
    })
    .map(drop)
}

fn encode_state(state: &impl Serialize) -> io::Result<Vec<u8>> {
    let bytes = serde_json::to_vec(state)?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(bad("Manager journal capacity exceeded"));
    }
    Ok(bytes)
}

fn persist_state(
    directory: &Path,
    bytes: &[u8],
    may_publish: impl Fn() -> io::Result<()>,
) -> io::Result<()> {
    may_publish()?;
    let mut pending = tempfile::NamedTempFile::new_in(directory)?;
    std::io::Write::write_all(&mut pending, bytes)?;
    pending.as_file().sync_all()?;
    may_publish()?;
    pending
        .persist(directory.join("journal.json"))
        .map_err(|e| e.error)?;
    File::open(directory)?.sync_all()?;
    may_publish()
}

fn check_write_deadline(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "Manager journal shutdown deadline elapsed",
        ));
    }
    Ok(())
}
