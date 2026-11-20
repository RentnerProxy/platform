mod catalog;
mod filesystem;
mod package;
mod transport;

#[cfg(test)]
#[path = "../tests/private/app_install.rs"]
pub(crate) mod tests;

use std::{
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
    process::ExitCode,
};

use marketplace_artifacts::{invalid, parse_json, read_file};
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub(crate) use package::{UI_ASSET_LIMIT, UI_DOCUMENT_LIMIT, parse_ui_api};
use rentnerproxy_app_contracts::{Contracts, ManifestEnvironment};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Config {
    store_directory: PathBuf,
    pinned_root: PathBuf,
    repository_url: String,
    engine_capabilities: Vec<String>,
}

pub struct Installer {
    config: Config,
    target: &'static str,
    pinned_root: Vec<u8>,
    contracts: Contracts,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StagedPackage {
    pub directory: PathBuf,
    pub manifest: Value,
    pub archive_sha256: String,
    pub manifest_sha256: String,
    pub catalog_revision: u64,
}

impl Installer {
    pub fn open(config: &Path) -> io::Result<Self> {
        let target = match (std::env::consts::OS, std::env::consts::ARCH) {
            ("linux", "x86_64") => "linux-amd64",
            ("linux", "aarch64") => "linux-arm64",
            _ => {
                return Err(io::Error::other(
                    "Native app installation requires Linux AMD64 or ARM64",
                ));
            }
        };
        filesystem::check_root_path(config, false)?;
        let config: Config = serde_json::from_value(parse_json(&read_file(config, 16 * 1024)?)?)?;
        filesystem::check_root_path(&config.store_directory, true)?;
        filesystem::check_root_path(&config.pinned_root, false)?;
        transport::repository_url(&config.repository_url)?;
        let pinned_root = read_file(&config.pinned_root, 512 * 1024)?;
        for name in &config.engine_capabilities {
            if !matches!(
                name.as_str(),
                "caddy.load-balancing.v1" | "caddy.crowdsec.v1"
            ) {
                return Err(invalid("Unknown installed engine capability"));
            }
        }
        Ok(Self {
            config,
            target,
            pinned_root,
            contracts: Contracts::new().map_err(invalid_contract)?,
        })
    }

    fn lock(&self) -> io::Result<File> {
        filesystem::lock(&self.config.store_directory)
    }

    /// Refresh signed metadata before selecting or downloading an exact release.
    pub fn stage(&self, app_id: &str, version: &str) -> io::Result<StagedPackage> {
        let _lock = self.lock()?;
        let transport = transport::Http::new(&self.config.repository_url)?;
        let catalog = self.refresh(
            |path, limit| transport.metadata(path, limit),
            OffsetDateTime::now_utc(),
        )?;
        self.prepare(&catalog, app_id, version, None, |asset| {
            transport.archive(asset)
        })
    }

    /// Reauthenticate the last accepted repository and reconstruct from a verified local archive.
    pub fn recover(
        &self,
        app_id: &str,
        version: &str,
        archive_sha256: &str,
    ) -> io::Result<StagedPackage> {
        let _lock = self.lock()?;
        let (_, catalog) = self
            .checkpoint()?
            .ok_or_else(|| invalid("No verified catalog checkpoint"))?;
        self.prepare::<io::Empty>(&catalog, app_id, version, Some(archive_sha256), |_| {
            Err(invalid("Verified archive is missing"))
        })
    }

    fn prepare<R: Read>(
        &self,
        trusted: &marketplace_app_catalog::TrustedPackageCatalog,
        app_id: &str,
        version: &str,
        expected_hash: Option<&str>,
        fetch: impl FnOnce(&rentnerproxy_app_contracts::DownloadAsset<'_>) -> io::Result<R>,
    ) -> io::Result<StagedPackage> {
        let document = parse_json(trusted.catalog_bytes())?;
        let catalog = self
            .contracts
            .validate_catalog(&document)
            .map_err(invalid_contract)?;
        let package = catalog
            .package(app_id, version, self.target)
            .ok_or_else(|| {
                invalid("App release is revoked, missing, or unavailable for this target")
            })?;
        if expected_hash.is_some_and(|hash| hash != package.archive_sha256()) {
            return Err(invalid(
                "Recorded package identity differs from the signed catalog",
            ));
        }
        let capabilities: Vec<_> = self
            .config
            .engine_capabilities
            .iter()
            .map(String::as_str)
            .collect();
        let environment = ManifestEnvironment {
            target: self.target,
            runtime_profile: "rentnerproxy-linux-v1",
            platform_api: "1.0.0",
            app_protocol: "1.0.0",
            ui_bridge: Some("1.0.0"),
            engine_capabilities: &capabilities,
        };
        self.contracts
            .check_manifest_compatibility(package.manifest(), &environment)
            .map_err(invalid_contract)?;
        let directory = package::stage(
            &self.config.store_directory,
            &package,
            self.target,
            expected_hash.is_none(),
            fetch,
        )?;
        Ok(StagedPackage {
            directory,
            manifest: package.manifest().clone(),
            archive_sha256: package.archive_sha256().to_owned(),
            manifest_sha256: package.manifest_sha256().to_owned(),
            catalog_revision: document["revision"]
                .as_f64()
                .ok_or_else(|| invalid("Missing catalog revision"))?
                as u64,
        })
    }
}

fn invalid_contract(error: rentnerproxy_app_contracts::ContractError) -> io::Error {
    invalid(error.code())
}

pub fn run_app_stage(mut args: impl Iterator<Item = String>) -> ExitCode {
    let (Some(config), Some(id), Some(version), None) =
        (args.next(), args.next(), args.next(), args.next())
    else {
        eprintln!("Expected --app-stage CONFIG APP_ID VERSION");
        return ExitCode::FAILURE;
    };
    match Installer::open(Path::new(&config)).and_then(|manager| manager.stage(&id, &version)) {
        Ok(package) => {
            println!("{}", serde_json::json!(package));
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("Application staging failed: {error}");
            ExitCode::FAILURE
        }
    }
}
