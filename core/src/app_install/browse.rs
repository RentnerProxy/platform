use std::io;

use marketplace_app_catalog::TrustedPackageCatalog;
use marketplace_artifacts::{invalid, parse_json};
use serde::Serialize;
use serde_json::Value;
use time::OffsetDateTime;

use super::{Installer, StagedPackage, invalid_contract, requires_grants, transport};

#[derive(Serialize)]
#[cfg_attr(test, derive(serde::Deserialize))]
#[serde(rename_all = "camelCase")]
pub(crate) struct CatalogEntry {
    pub(crate) app_id: String,
    pub(crate) version: String,
    pub(crate) archive_sha256: String,
    name: String,
    summary: String,
    publisher: String,
    has_ui: bool,
    availability: Availability,
}

#[derive(Serialize)]
#[cfg_attr(test, derive(serde::Deserialize))]
#[serde(rename_all = "camelCase")]
enum Availability {
    Available,
    Incompatible,
    GrantsRequired,
}

impl CatalogEntry {
    pub(crate) fn is_available(&self) -> bool {
        matches!(self.availability, Availability::Available)
    }
}

impl Installer {
    pub(crate) fn browse_cached(&self) -> io::Result<Option<Vec<CatalogEntry>>> {
        self.checkpoint()?
            .map(|(_, catalog)| self.catalog_entries(&catalog))
            .transpose()
    }

    pub(crate) fn browse_latest(&self) -> io::Result<Vec<CatalogEntry>> {
        let http = transport::Http::new(&self.config.repository_url)?;
        let catalog = self.refresh_in_background(
            |path, limit| http.metadata(path, limit),
            OffsetDateTime::now_utc(),
        )?;
        self.catalog_entries(&catalog)
    }

    pub(crate) fn stage_selected(
        &self,
        app_id: &str,
        version: &str,
        archive_sha256: &str,
    ) -> io::Result<StagedPackage> {
        self.stage_catalog(app_id, version, Some(archive_sha256))
    }

    pub(super) fn catalog_entries(
        &self,
        trusted: &TrustedPackageCatalog,
    ) -> io::Result<Vec<CatalogEntry>> {
        let document = parse_json(trusted.catalog_bytes())?;
        let catalog = self
            .contracts
            .validate_catalog(&document)
            .map_err(invalid_contract)?;
        let releases = catalog.releases();
        let mut entries = Vec::with_capacity(releases.len());
        for release in releases {
            let Some(package) = release["packages"].as_array().and_then(|packages| {
                packages
                    .iter()
                    .find(|package| package["manifest"]["target"] == self.target)
            }) else {
                continue;
            };
            let manifest = &package["manifest"];
            let availability = if self.check_compatibility(manifest).is_err() {
                Availability::Incompatible
            } else if requires_grants(manifest) {
                Availability::GrantsRequired
            } else {
                Availability::Available
            };
            entries.push(CatalogEntry {
                app_id: field(release, "appId")?.to_owned(),
                version: field(release, "version")?.to_owned(),
                archive_sha256: field(&package["archive"], "sha256")?.to_owned(),
                name: field(&manifest["display"], "name")?.to_owned(),
                summary: field(&manifest["display"], "summary")?.to_owned(),
                publisher: field(&release["publisher"], "name")?.to_owned(),
                has_ui: manifest["ui"].is_object(),
                availability,
            });
        }
        Ok(entries)
    }
}

fn field<'a>(value: &'a Value, name: &'static str) -> io::Result<&'a str> {
    value[name]
        .as_str()
        .ok_or_else(|| invalid("Missing signed catalog display field"))
}
