use super::{
    bad,
    journal::{self, Journal, Removal, Slot},
    read_data, runtime, storage, verify_recovered_release,
};
use crate::{app_install::StagedPackage, appliance_process::verify_uid_stopped};
use marketplace_artifacts::read_file;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    fs::{self, File},
    io,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

const MANAGER: &str = "/var/lib/rentnerproxy/app-manager";
const APPS: &str = "/var/lib/rentnerproxy/apps";
const MARKER: &str = "portable-restore.json";

#[derive(Clone, Deserialize, Serialize)]
#[serde(transparent)]
pub(crate) struct Inventory(BTreeMap<String, Slot>);

impl Inventory {
    pub fn validate(&self) -> io::Result<()> {
        journal::validate_portable_inventory(&self.0)?;
        if self.0.values().any(|slot| {
            !catalog_app_id(&slot.app_id)
                || slot.authority_recorded.is_none()
                || slot.pending_fence
                || slot.recovery_required
                || slot.grants_uncertain == Some(true)
                || matches!(slot.removal, Removal::Removing | Removal::Purging)
                || (slot.desired_running
                    && (slot.removal != Removal::Installed || slot.active.is_none()))
                || slot.database_provisioned != slot.written.is_some()
                || (slot.database_provisioned && slot.storage_claimed == Some(false))
        }) {
            return Err(bad("App inventory is not in a recoverable state"));
        }
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn metadata(&self) -> io::Result<Value> {
        Ok(serde_json::to_value(&self.0)?)
    }

    pub fn databases(&self) -> Vec<u32> {
        let mut uids: Vec<_> = self
            .0
            .values()
            .filter(|slot| slot.database_provisioned)
            .map(|slot| slot.uid)
            .collect();
        uids.sort_unstable();
        uids
    }

    pub fn package_digests(&self) -> BTreeSet<&str> {
        self.0
            .values()
            .flat_map(|slot| [&slot.active, &slot.previous, &slot.candidate])
            .flatten()
            .map(|release| release.archive_sha256.as_str())
            .collect()
    }

    pub fn verify_packages(
        &self,
        mut recover: impl FnMut(&str, &str, &str) -> io::Result<StagedPackage>,
    ) -> io::Result<()> {
        for slot in self.0.values() {
            for release in [&slot.active, &slot.previous, &slot.candidate]
                .into_iter()
                .flatten()
            {
                let package = recover(&slot.app_id, &release.version, &release.archive_sha256)?;
                verify_recovered_release(&package, &slot.app_id, release)?;
                if slot.active.as_ref() == Some(release) {
                    let declared = package.manifest.get("data").map(read_data).transpose()?;
                    if declared != slot.written {
                        return Err(bad(
                            "Recovered app data version differs from the active package",
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    /// Locks the writer of every captured UID and every UID that a replacing
    /// restore retires. A new target also needs each captured UID unused,
    /// apart from the persistent storage that the restore retires first.
    pub fn lock_writers(
        &self,
        backup: &BackupJournal,
        retiring: &BTreeSet<u32>,
        vacant: bool,
    ) -> io::Result<BTreeMap<u32, File>> {
        let mut writers = BTreeMap::new();
        for uid in self
            .0
            .values()
            .map(|slot| slot.uid)
            .chain(retiring.iter().copied())
        {
            if let Entry::Vacant(entry) = writers.entry(uid) {
                let lock = backup.0.writer(uid)?;
                verify_uid_stopped(uid)?;
                entry.insert(lock);
            }
        }
        for slot in self.0.values() {
            if vacant && !runtime::uid_reusable(slot.uid, retiring.contains(&slot.uid))? {
                return Err(bad("Restored application UID is already in use"));
            }
        }
        Ok(writers)
    }

    pub fn claim_storage(&self, uid: u32) -> io::Result<PathBuf> {
        let (id, slot) = self
            .0
            .iter()
            .find(|(_, slot)| slot.uid == uid)
            .ok_or_else(|| bad("Unknown restored app UID"))?;
        let mut reservation = slot.clone();
        // An empty destination has not yet materialized this historical storage claim.
        reservation.storage_claimed = Some(false);
        storage::claim(id, &reservation)?;
        Ok(Path::new(APPS).join(uid.to_string()).join("data"))
    }
}

fn catalog_app_id(id: &str) -> bool {
    fn segment(value: &str, limit: usize) -> bool {
        let bytes = value.as_bytes();
        bytes.len() <= limit
            && bytes.first().is_some_and(u8::is_ascii_lowercase)
            && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
            && bytes
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
    }
    id.split_once('.')
        .is_some_and(|(namespace, name)| segment(namespace, 32) && segment(name, 64))
}

pub(crate) async fn provision_database(uid: u32, writer: &File) -> io::Result<()> {
    runtime::provision(uid, true, writer).await
}

pub(crate) struct BackupJournal(Journal);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Destination {
    Fresh,
    /// Installed apps are retired before the backup is restored.
    Replacing,
    Resuming,
    Published,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreMarker {
    digest: String,
    complete: bool,
    // Older markers have no retirement in progress.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    retiring: bool,
}

fn destination(
    marker: Option<&RestoreMarker>,
    digest: &str,
    installed: bool,
    published: bool,
) -> io::Result<Destination> {
    match marker {
        // An interrupted retirement continues for the backup that authorized it.
        Some(marker) if marker.digest == digest && marker.retiring => Ok(Destination::Replacing),
        Some(marker) if marker.digest == digest && !installed && !marker.complete => {
            Ok(Destination::Resuming)
        }
        // The journal is published last. A crash before marking completion
        // must not cause us to rewrite a database that is already consistent.
        // A completed restore of this backup that no app has changed since is
        // also left as it is, so a lost maintenance response can be retried.
        Some(marker) if marker.digest == digest && published => Ok(Destination::Published),
        Some(marker) if marker.digest == digest && !marker.complete => {
            Err(bad("Portable restore journal has changed"))
        }
        Some(marker) if !marker.complete => Err(bad(
            "Portable recovery requires the same interrupted backup",
        )),
        // A completed earlier restore leaves no obligation on this target.
        _ if installed => Ok(Destination::Replacing),
        _ => Ok(Destination::Fresh),
    }
}

fn marker_path() -> PathBuf {
    Path::new(MANAGER).join(MARKER)
}

fn read_marker() -> io::Result<Option<RestoreMarker>> {
    let path = marker_path();
    match fs::symlink_metadata(&path) {
        Ok(info)
            if info.is_file()
                && info.uid() == 0
                && info.nlink() == 1
                && info.mode() & 0o7777 == 0o600 => {}
        Ok(_) => return Err(bad("Unsafe portable restore marker")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    }
    let marker: RestoreMarker = serde_json::from_slice(&read_file(&path, 1024)?)?;
    if !crate::app_backup::valid_portable_digest(&marker.digest)
        || (marker.retiring && marker.complete)
    {
        return Err(bad("Invalid portable restore marker"));
    }
    Ok(Some(marker))
}

fn write_marker(digest: &str, complete: bool, retiring: bool) -> io::Result<()> {
    let mut marker = tempfile::NamedTempFile::new_in(MANAGER)?;
    serde_json::to_writer(
        marker.as_file_mut(),
        &RestoreMarker {
            digest: digest.to_owned(),
            complete,
            retiring,
        },
    )?;
    marker.as_file().sync_all()?;
    marker.persist(marker_path()).map_err(|error| error.error)?;
    File::open(MANAGER)?.sync_all()
}

pub(super) fn require_ready_to_start() -> io::Result<()> {
    if read_marker()?.is_some_and(|marker| !marker.complete) {
        return Err(bad(
            "Finish the pending portable app restore before starting the app manager",
        ));
    }
    Ok(())
}

impl BackupJournal {
    pub fn open() -> io::Result<Self> {
        Journal::open(Path::new(MANAGER)).map(Self)
    }

    pub fn capture(&self) -> io::Result<Inventory> {
        require_ready_to_start()?;
        let inventory = Inventory(self.0.slots().clone());
        inventory.validate()?;
        Ok(inventory)
    }

    pub fn destination(&self, digest: &str, inventory: &Inventory) -> io::Result<Destination> {
        let slots = self.0.slots();
        let published = serde_json::to_value(slots)? == inventory.metadata()?;
        destination(
            read_marker()?.as_ref(),
            digest,
            !slots.is_empty(),
            published,
        )
    }

    /// The UIDs of every installation that a replacing restore retires.
    pub fn installed_uids(&self) -> BTreeSet<u32> {
        self.0.slots().values().map(|slot| slot.uid).collect()
    }

    pub fn check_retirement(&self) -> io::Result<()> {
        storage::retire(self.0.slots(), false)
    }

    /// Records the retirement before any installed app storage or database changes,
    /// so an interrupted restore resumes it only for the same backup.
    pub fn begin_retirement(&self, digest: &str) -> io::Result<()> {
        write_marker(digest, false, true)
    }

    pub fn retire_storage(&self) -> io::Result<()> {
        storage::retire(self.0.slots(), true)
    }

    /// Forgets the retired installations, then resumes the restore as for an empty target.
    pub fn finish_retirement(&mut self, digest: &str) -> io::Result<()> {
        self.0.retire_installations()?;
        write_marker(digest, false, false)
    }

    pub fn begin(&self, digest: &str) -> io::Result<()> {
        write_marker(digest, false, false)
    }

    pub fn finish(&mut self, digest: &str, inventory: Inventory) -> io::Result<()> {
        if self.0.slots().is_empty() {
            self.0.restore_installations(inventory.0)?;
        }
        write_marker(digest, true, false)
    }
}

#[cfg(test)]
#[path = "../../tests/private/app_manager/portable_backup.rs"]
mod tests;
