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
    collections::{BTreeMap, BTreeSet},
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

    pub fn lock_writers(
        &self,
        backup: &BackupJournal,
        fresh: bool,
    ) -> io::Result<BTreeMap<u32, File>> {
        self.0
            .values()
            .map(|slot| {
                let lock = backup.0.writer(slot.uid)?;
                verify_uid_stopped(slot.uid)?;
                if fresh && !runtime::uid_available(slot.uid)? {
                    return Err(bad("Restored application UID is already in use"));
                }
                Ok((slot.uid, lock))
            })
            .collect()
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

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Destination {
    Fresh,
    Resuming,
    Published,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreMarker {
    digest: String,
    complete: bool,
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
    if !crate::app_backup::valid_portable_digest(&marker.digest) {
        return Err(bad("Invalid portable restore marker"));
    }
    Ok(Some(marker))
}

fn write_marker(digest: &str, complete: bool) -> io::Result<()> {
    let mut marker = tempfile::NamedTempFile::new_in(MANAGER)?;
    serde_json::to_writer(
        marker.as_file_mut(),
        &RestoreMarker {
            digest: digest.to_owned(),
            complete,
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
        match read_marker()? {
            None if self.0.slots().is_empty() => Ok(Destination::Fresh),
            Some(marker) if marker.digest == digest => {
                if self.0.slots().is_empty() && !marker.complete {
                    return Ok(Destination::Resuming);
                }
                // The journal is published last. A crash before marking completion
                // must not cause us to rewrite a database that is already consistent.
                if serde_json::to_value(self.0.slots())? == inventory.metadata()? {
                    return Ok(Destination::Published);
                }
                Err(bad("Portable restore journal has changed"))
            }
            _ => Err(bad(
                "Portable recovery requires an empty target or the same interrupted backup",
            )),
        }
    }

    pub fn begin(&self, digest: &str) -> io::Result<()> {
        write_marker(digest, false)
    }

    pub fn finish(&mut self, digest: &str, inventory: Inventory) -> io::Result<()> {
        if self.0.slots().is_empty() {
            self.0.restore_installations(inventory.0)?;
        }
        write_marker(digest, true)
    }
}
