use super::{bad, valid_id};
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

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Grant {
    pub capability: Capability,
    pub resource_id: String,
    pub allow_service: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_key: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Capability {
    pub id: String,
    pub scope: String,
}

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

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Data {
    pub target_version: u32,
    pub read_versions: Vec<u32>,
    pub write_versions: Vec<u32>,
    pub migrations: Vec<serde_json::Value>,
}

pub(super) fn compatible(written: Option<&Data>, next: Option<&Data>) -> bool {
    match (written, next) {
        (None, None) => true,
        (None, Some(next)) => !next
            .migrations
            .iter()
            .any(|m| m["fromVersion"].as_f64() == Some(0.0)),
        (Some(a), Some(b)) => {
            a.target_version == b.target_version
                && a.write_versions
                    .iter()
                    .all(|v| b.read_versions.contains(v) && b.write_versions.contains(v))
        }
        (Some(_), None) => false,
    }
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
}

impl Slot {
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

    pub fn accepts(&self, release: &Release, data: Option<&Data>) -> bool {
        compatible(self.written.as_ref(), data)
            && (self
                .active
                .as_ref()
                .is_none_or(|active| active.same_package(release))
                || compatible(data, self.written.as_ref()))
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
        let mut uids = BTreeSet::new();
        if state.format_version != 1
            || state.installations.len() > LIMIT
            || state.installations.iter().any(|(id, s)| {
                !valid_id(id)
                    || !(20000..=59999).contains(&s.uid)
                    || !uids.insert(s.uid)
                    || s.generation > super::MAX_GENERATION
                    || s.pending_fence && s.generation == 0
            })
        {
            return Err(bad("Invalid manager journal"));
        }
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
    pub fn save(&mut self, id: &str, slot: Slot) -> io::Result<()> {
        self.writable()?;
        let mut next = self.state.as_ref().clone();
        next.installations.insert(id.to_owned(), slot);
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

fn encode_state(state: &State) -> io::Result<Vec<u8>> {
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
