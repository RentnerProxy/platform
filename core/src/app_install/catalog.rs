use std::{collections::BTreeMap, io, path::Path};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use marketplace_app_catalog::{CatalogError, TrustedPackageCatalog, read_package_catalog};
use marketplace_artifacts::{digest, invalid, read_file};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::{Installer, filesystem};

const METADATA_BUDGET: usize = 64 * 1024 * 1024;
const MAX_FILES: usize = 5300;
pub(super) const CHECKPOINT: &str = "catalog-checkpoint.json";
pub(super) const CHECKPOINT_LIMIT: u64 = 96 * 1024 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Checkpoint {
    accepted_at: i64,
    pin_sha256: String,
    files: BTreeMap<String, String>,
}

fn read(
    mut fetch: impl FnMut(&str, usize) -> io::Result<Option<Vec<u8>>>,
    pin: &[u8],
    now: OffsetDateTime,
    previous: Option<&TrustedPackageCatalog>,
) -> io::Result<TrustedPackageCatalog> {
    let mut remaining = METADATA_BUDGET;
    let mut requests = 0;
    read_package_catalog(
        |name, limit| {
            requests += 1;
            if requests > MAX_FILES {
                return Err(CatalogError::new("Catalog exceeds its file budget"));
            }
            let bytes = fetch(name, limit.min(remaining))
                .map_err(|error| CatalogError::new(error.to_string()))?;
            if let Some(bytes) = &bytes {
                if bytes.len() > limit.min(remaining) {
                    return Err(CatalogError::new("Catalog exceeds its byte budget"));
                }
                remaining -= bytes.len();
            }
            Ok(bytes)
        },
        pin,
        now,
        previous,
    )
    .map_err(|error| invalid(error.to_string()))
}

impl Installer {
    pub(super) fn checkpoint(&self) -> io::Result<Option<(i64, TrustedPackageCatalog)>> {
        let bytes = match read_file(
            &self.config.store_directory.join(CHECKPOINT),
            CHECKPOINT_LIMIT,
        ) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let checkpoint: Checkpoint = serde_json::from_slice(&bytes)?;
        drop(bytes);
        if checkpoint.pin_sha256 != digest(&self.pinned_root) || checkpoint.files.len() > MAX_FILES
        {
            return Err(invalid(
                "Stored catalog differs from the configured trust root or exceeds its budget",
            ));
        }
        let accepted = OffsetDateTime::from_unix_timestamp(checkpoint.accepted_at)
            .map_err(io::Error::other)?;
        let catalog = checkpoint.verify(&self.pinned_root, accepted, None)?;
        Ok(Some((checkpoint.accepted_at, catalog)))
    }

    pub(super) fn refresh(
        &self,
        fetch: impl FnMut(&str, usize) -> io::Result<Option<Vec<u8>>>,
        now: OffsetDateTime,
    ) -> io::Result<TrustedPackageCatalog> {
        let (next, catalog) = self.fetch_checkpoint(fetch, now)?;
        write_checkpoint(&self.config.store_directory, &next)?;
        Ok(catalog)
    }

    #[cfg(any(
        test,
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    pub(super) fn refresh_in_background(
        &self,
        fetch: impl FnMut(&str, usize) -> io::Result<Option<Vec<u8>>>,
        now: OffsetDateTime,
    ) -> io::Result<TrustedPackageCatalog> {
        let (next, _) = self.fetch_checkpoint(fetch, now)?;
        let _lock = self.lock()?;
        // Stage may have committed newer metadata while this refresh was fetching.
        let catalog = next.verify(&self.pinned_root, now, self.previous(now)?.as_ref())?;
        write_checkpoint(&self.config.store_directory, &next)?;
        Ok(catalog)
    }

    fn previous(&self, now: OffsetDateTime) -> io::Result<Option<TrustedPackageCatalog>> {
        match self.checkpoint()? {
            Some((accepted_at, _)) if accepted_at > now.unix_timestamp() => {
                Err(invalid("Local time is earlier than the accepted catalog"))
            }
            previous => Ok(previous.map(|(_, catalog)| catalog)),
        }
    }

    fn fetch_checkpoint(
        &self,
        mut fetch: impl FnMut(&str, usize) -> io::Result<Option<Vec<u8>>>,
        now: OffsetDateTime,
    ) -> io::Result<(Checkpoint, TrustedPackageCatalog)> {
        let previous = self.previous(now)?;
        let mut next = Checkpoint {
            accepted_at: now.unix_timestamp(),
            pin_sha256: digest(&self.pinned_root),
            files: BTreeMap::new(),
        };
        let catalog = read(
            |name, limit| {
                let bytes = fetch(name, limit)?;
                if let Some(bytes) = &bytes {
                    if bytes.len() > limit {
                        return Err(invalid("Oversized catalog entry"));
                    }
                    next.files.insert(name.to_owned(), STANDARD.encode(bytes));
                }
                Ok(bytes)
            },
            &self.pinned_root,
            now,
            previous.as_ref(),
        )?;
        Ok((next, catalog))
    }
}

impl Checkpoint {
    fn verify(
        &self,
        pin: &[u8],
        at: OffsetDateTime,
        previous: Option<&TrustedPackageCatalog>,
    ) -> io::Result<TrustedPackageCatalog> {
        read(
            |name, limit| {
                self.files
                    .get(name)
                    .map(|raw| {
                        if raw.len() > limit.div_ceil(3) * 4 {
                            return Err(invalid("Oversized checkpoint entry"));
                        }
                        STANDARD.decode(raw).map_err(io::Error::other)
                    })
                    .transpose()
            },
            pin,
            at,
            previous,
        )
    }
}

fn write_checkpoint(directory: &Path, checkpoint: &Checkpoint) -> io::Result<()> {
    let mut file = tempfile::NamedTempFile::new_in(directory)?;
    serde_json::to_writer(file.as_file_mut(), checkpoint)?;
    file.as_file().sync_all()?;
    file.persist(directory.join(CHECKPOINT))
        .map_err(|error| error.error)?;
    filesystem::sync_directory(directory)
}
