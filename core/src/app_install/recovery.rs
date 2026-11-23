use super::{
    Config, Installer, PackageSource, StagedPackage,
    catalog::{CHECKPOINT, CHECKPOINT_LIMIT},
    catalog_revision, filesystem,
    package::COMPRESSED_LIMIT,
};
use crate::app_backup::valid_portable_digest;
use marketplace_app_catalog::TrustedPackageCatalog;
use marketplace_artifacts::{copy_file, file_identity, invalid, parse_json};
use rentnerproxy_app_contracts::Contracts;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io,
    path::{Path, PathBuf},
};
use time::OffsetDateTime;

pub(crate) const MAX_CHECKPOINT_BYTES: u64 = CHECKPOINT_LIMIT;
pub(crate) const MAX_PACKAGE_BYTES: u64 = COMPRESSED_LIMIT;
const WORKSPACE: &str = ".app-recovery-";

pub(crate) struct RecoverySource<'a> {
    installer: &'a Installer,
    _lock: File,
    catalog: TrustedPackageCatalog,
}

pub(crate) struct RecoveryTarget<'a> {
    installer: &'a Installer,
    _lock: File,
    _directory: tempfile::TempDir,
    staged: Installer,
    catalog: TrustedPackageCatalog,
    retained_catalog: Option<Value>,
    archives: Vec<String>,
}

fn checked_checkpoint(installer: &Installer) -> io::Result<Option<TrustedPackageCatalog>> {
    installer
        .checkpoint()?
        .map(|(accepted_at, catalog)| {
            if accepted_at > OffsetDateTime::now_utc().unix_timestamp() {
                return Err(invalid("Catalog checkpoint was accepted in the future"));
            }
            Ok(catalog)
        })
        .transpose()
}

fn select_recovery_catalog(
    staged: &Installer,
    archived: TrustedPackageCatalog,
    destination: Option<TrustedPackageCatalog>,
) -> io::Result<(TrustedPackageCatalog, Option<Value>)> {
    let Some(destination) = destination else {
        return Ok((archived, None));
    };
    let archived_document = parse_json(archived.catalog_bytes())?;
    let destination_document = parse_json(destination.catalog_bytes())?;
    let archived_revision = catalog_revision(&archived_document)?;
    let destination_revision = catalog_revision(&destination_document)?;
    if archived_revision == destination_revision
        && archived.catalog_bytes() != destination.catalog_bytes()
    {
        return Err(invalid(
            "Recovery catalog reuses a different accepted revision",
        ));
    }
    if archived_revision <= destination_revision {
        return Ok((archived, Some(destination_document)));
    }

    // Advance an older checkpoint only when the archived TUF history extends its
    // root and online role floors and carries every already accepted revocation.
    let (_, authenticated) = staged
        .checkpoint_with_floor(Some(&destination))?
        .ok_or_else(|| invalid("Missing archived catalog checkpoint"))?;
    preserve_revocations(&destination_document, &archived_document)?;
    Ok((authenticated, None))
}

fn preserve_revocations(previous: &Value, next: &Value) -> io::Result<()> {
    fn key(entry: &Value) -> (Option<&str>, Option<&str>) {
        (entry["appId"].as_str(), entry["version"].as_str())
    }
    let previous = previous["revocations"]
        .as_array()
        .ok_or_else(|| invalid("Missing previous catalog revocations"))?;
    let next = next["revocations"]
        .as_array()
        .ok_or_else(|| invalid("Missing recovery catalog revocations"))?;
    let next: BTreeMap<_, _> = next.iter().map(|entry| (key(entry), entry)).collect();
    if previous
        .iter()
        .any(|entry| next.get(&key(entry)) != Some(&entry))
    {
        return Err(invalid(
            "Recovery catalog removes or changes an accepted revocation",
        ));
    }
    Ok(())
}

fn recover_recorded(
    installer: &Installer,
    catalog: &TrustedPackageCatalog,
    id: &str,
    version: &str,
    digest: &str,
) -> io::Result<StagedPackage> {
    installer.prepare::<io::Empty>(
        catalog,
        id,
        version,
        PackageSource::Recorded(digest),
        |_| Err(invalid("Verified recovery archive is missing")),
    )
}

impl Installer {
    pub(crate) fn recovery_source(&self) -> io::Result<RecoverySource<'_>> {
        let lock = self.lock()?;
        let catalog = checked_checkpoint(self)?
            .ok_or_else(|| invalid("App backup requires a verified catalog checkpoint"))?;
        Ok(RecoverySource {
            installer: self,
            _lock: lock,
            catalog,
        })
    }

    pub(crate) fn prepare_recovery(
        &self,
        checkpoint: &Path,
        archives: &BTreeMap<String, PathBuf>,
    ) -> io::Result<RecoveryTarget<'_>> {
        let lock = self.lock()?;
        filesystem::clean_workspaces(&self.config.store_directory, WORKSPACE)?;
        let directory = filesystem::private_workspace(&self.config.store_directory, WORKSPACE)?;
        let store = directory.path();
        filesystem::directory(&store.join("archives"), 0o700)?;
        let staged = Self {
            config: Config {
                store_directory: store.to_owned(),
                pinned_root: self.config.pinned_root.clone(),
                repository_url: self.config.repository_url.clone(),
                engine_capabilities: self.config.engine_capabilities.clone(),
            },
            target: self.target,
            pinned_root: self.pinned_root.clone(),
            contracts: Contracts::new().map_err(super::invalid_contract)?,
        };
        materialize(checkpoint, &store.join(CHECKPOINT), CHECKPOINT_LIMIT)?;
        let archived = checked_checkpoint(&staged)?
            .ok_or_else(|| invalid("Missing archived catalog checkpoint"))?;
        let (catalog, retained_catalog) =
            select_recovery_catalog(&staged, archived, checked_checkpoint(self)?)?;
        let cache = self.config.store_directory.join("archives");
        match fs::symlink_metadata(&cache) {
            Ok(_) => filesystem::directory(&cache, 0o700)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let mut uncached = Vec::new();
        for (digest, archive) in archives {
            if !valid_portable_digest(digest) {
                return Err(invalid("Invalid recovery package identity"));
            }
            let target = store.join("archives").join(digest);
            materialize(archive, &target, COMPRESSED_LIMIT)?;
            let cached = cache.join(digest);
            match fs::symlink_metadata(&cached) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    uncached.push(digest.clone())
                }
                Ok(info) if info.is_file() => {
                    let identity = file_identity(&cached, COMPRESSED_LIMIT)?;
                    if identity.sha256 != *digest
                        || identity.size_bytes != fs::metadata(&target)?.len()
                    {
                        return Err(invalid(
                            "A conflicting cached archive prevents portable recovery",
                        ));
                    }
                }
                Ok(_) => return Err(invalid("Unsafe cached archive on recovery target")),
                Err(error) => return Err(error),
            }
        }
        Ok(RecoveryTarget {
            installer: self,
            _lock: lock,
            _directory: directory,
            staged,
            catalog,
            retained_catalog,
            archives: uncached,
        })
    }
}

fn materialize(path: &Path, destination: &Path, limit: u64) -> io::Result<()> {
    // The source is newly verified by the envelope reader in a private
    // workspace. Package and catalog signatures are checked independently.
    let info = fs::symlink_metadata(path)?;
    if !info.is_file() || info.len() > limit {
        return Err(invalid("Invalid staged recovery material"));
    }
    match fs::rename(path, destination) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::CrossesDevices => {
            copy_file(path, destination, limit, None)?;
        }
        Err(error) => return Err(error),
    }
    filesystem::sync_file(destination)
}

impl RecoverySource<'_> {
    pub fn recover(&self, id: &str, version: &str, digest: &str) -> io::Result<StagedPackage> {
        recover_recorded(self.installer, &self.catalog, id, version, digest)
    }

    pub fn checkpoint_path(&self) -> PathBuf {
        self.installer.config.store_directory.join(CHECKPOINT)
    }

    pub fn archive_path(&self, digest: &str) -> io::Result<PathBuf> {
        if !valid_portable_digest(digest) {
            return Err(invalid("Invalid recovery package identity"));
        }
        Ok(self
            .installer
            .config
            .store_directory
            .join("archives")
            .join(digest))
    }
}

impl RecoveryTarget<'_> {
    pub fn recover(&self, id: &str, version: &str, digest: &str) -> io::Result<StagedPackage> {
        let mut package = recover_recorded(&self.staged, &self.catalog, id, version, digest)?;
        // Preserve any independently observed rollback floor or revocation.
        if let Some(document) = &self.retained_catalog {
            let (local, revision) = self.installer.signed_package(document, id, version)?;
            let archive = self
                .staged
                .config
                .store_directory
                .join("archives")
                .join(digest);
            if local.archive_sha256() != digest
                || local.manifest_sha256() != package.manifest_sha256
                || local.release_assets().archive.size_bytes != fs::metadata(archive)?.len()
            {
                return Err(invalid("Recovery package conflicts with the local catalog"));
            }
            package.catalog_revision = package.catalog_revision.min(revision);
        }
        Ok(package)
    }

    pub fn publish(self) -> io::Result<()> {
        let store = &self.installer.config.store_directory;
        let archives = store.join("archives");
        filesystem::directory(&archives, 0o700)?;
        for digest in &self.archives {
            let from = self
                .staged
                .config
                .store_directory
                .join("archives")
                .join(digest);
            fs::rename(from, archives.join(digest))?;
        }
        filesystem::sync_directory(&archives)?;
        if self.retained_catalog.is_none() {
            let verified = self.staged.config.store_directory.join(CHECKPOINT);
            // Recovered packages remain tied to a historical checkpoint. Stage
            // and catalog-refresh still evaluate new metadata at the current time.
            fs::rename(verified, store.join(CHECKPOINT))?;
        }
        filesystem::sync_directory(store)
    }
}

#[cfg(test)]
#[path = "../../tests/private/app_install/recovery.rs"]
mod tests;
