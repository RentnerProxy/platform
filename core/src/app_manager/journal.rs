use super::{bad, valid_id};
use crate::app_ipc::filesystem::{lock_file, require_safe_parents};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Read},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
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
    _lock: File,
    state: State,
    poisoned: bool,
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
            _lock: guard,
            state,
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
        let mut next = self.state.clone();
        next.installations.insert(id.to_owned(), slot);
        let bytes = serde_json::to_vec(&next)?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err(bad("Manager journal capacity exceeded"));
        }
        self.poisoned = true;
        let mut pending = tempfile::NamedTempFile::new_in(&self.directory)?;
        std::io::Write::write_all(&mut pending, &bytes)?;
        pending.as_file().sync_all()?;
        pending
            .persist(self.directory.join("journal.json"))
            .map_err(|e| e.error)?;
        File::open(&self.directory)?.sync_all()?;
        self.state = next;
        self.poisoned = false;
        Ok(())
    }
}
