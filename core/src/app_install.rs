#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod appliance;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod browse;
mod catalog;
pub(crate) mod filesystem;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub(crate) mod grants;
mod package;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub(crate) mod recovery;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod target;
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

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub(crate) use browse::CatalogEntry;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub(crate) use package::{UI_ASSET_LIMIT, UI_DOCUMENT_LIMIT, parse_ui_api};
use rentnerproxy_app_contracts::{ContractError, Contracts, ManifestEnvironment};
use rentnerproxy_artifacts::{invalid, parse_json, read_file};
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(all(
    test,
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub(crate) use target::TargetSupport;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub(crate) use target::{InstalledRelease, TargetCheck, TargetEnvironment};
use time::OffsetDateTime;
#[cfg(all(
    test,
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub(crate) use transport::SourceUnavailable;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub(crate) use transport::{Source, unreachable_source};

/// The app runtime this platform release offers. The release requirements asset publishes the
/// same values (`web/src/config/app-requirements.config.ts`), so an older platform can check
/// installed apps against a newer release before its image changes.
pub(crate) const RUNTIME_PROFILE: &str = "rentnerproxy-linux-v1";
pub(crate) const PROTOCOL_VERSION: &str = "1.0.0";

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

#[derive(Clone, Copy)]
enum PackageSource<'a> {
    Catalog(Option<&'a str>),
    Recorded(&'a str),
}

impl Installer {
    pub fn open(config: &Path) -> io::Result<Self> {
        Self::with_config(Self::read_config(config)?)
    }

    fn read_config(path: &Path) -> io::Result<Config> {
        filesystem::check_root_path(path, false)?;
        Ok(serde_json::from_value(parse_json(&read_file(
            path,
            16 * 1024,
        )?)?)?)
    }

    fn with_config(config: Config) -> io::Result<Self> {
        let target = match (std::env::consts::OS, std::env::consts::ARCH) {
            ("linux", "x86_64") => "linux-amd64",
            ("linux", "aarch64") => "linux-arm64",
            _ => {
                return Err(io::Error::other(
                    "Native app installation requires Linux AMD64 or ARM64",
                ));
            }
        };
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
        self.stage_catalog(app_id, version, None, |_| Ok(()))
    }

    /// `gate` sees the freshly signed manifest and may refuse the release before any download.
    fn stage_catalog(
        &self,
        app_id: &str,
        version: &str,
        selected_hash: Option<&str>,
        gate: impl FnOnce(&Value) -> io::Result<()>,
    ) -> io::Result<StagedPackage> {
        let _lock = self.lock()?;
        let transport = transport::Http::new(&self.config.repository_url)?;
        let catalog = self
            .refresh(
                |path, limit| transport.metadata(path, limit),
                OffsetDateTime::now_utc(),
            )
            .map_err(|error| {
                catalog_outage(error, || {
                    // Ask the package source for the release that the accepted catalog lists.
                    let (_, accepted) = self.checkpoint().ok()??;
                    let document = parse_json(accepted.catalog_bytes()).ok()?;
                    let (package, _) = self.signed_package(&document, app_id, version).ok()?;
                    Some(transport.package_source_answers(&package.release_assets().archive))
                })
            })?;
        self.prepare_gated(
            &catalog,
            app_id,
            version,
            PackageSource::Catalog(selected_hash),
            gate,
            |asset| transport.archive(asset),
        )
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
        self.prepare::<io::Empty>(
            &catalog,
            app_id,
            version,
            PackageSource::Recorded(archive_sha256),
            |_| Err(invalid("Verified archive is missing")),
        )
    }

    fn prepare<R: Read>(
        &self,
        trusted: &rentnerproxy_app_catalog::TrustedPackageCatalog,
        app_id: &str,
        version: &str,
        source: PackageSource<'_>,
        fetch: impl FnOnce(&rentnerproxy_app_contracts::DownloadAsset<'_>) -> io::Result<R>,
    ) -> io::Result<StagedPackage> {
        self.prepare_gated(trusted, app_id, version, source, |_| Ok(()), fetch)
    }

    /// Verify the signed release and stage it. `gate` sees the signed manifest after the
    /// compatibility check, before `package::stage` fetches or extracts anything.
    fn prepare_gated<R: Read>(
        &self,
        trusted: &rentnerproxy_app_catalog::TrustedPackageCatalog,
        app_id: &str,
        version: &str,
        source: PackageSource<'_>,
        gate: impl FnOnce(&Value) -> io::Result<()>,
        fetch: impl FnOnce(&rentnerproxy_app_contracts::DownloadAsset<'_>) -> io::Result<R>,
    ) -> io::Result<StagedPackage> {
        let document = parse_json(trusted.catalog_bytes())?;
        let (package, catalog_revision) = self.signed_package(&document, app_id, version)?;
        let expected_hash = match source {
            PackageSource::Catalog(hash) => hash,
            PackageSource::Recorded(hash) => Some(hash),
        };
        if expected_hash.is_some_and(|hash| hash != package.archive_sha256()) {
            return Err(invalid("Package identity differs from the signed catalog"));
        }
        self.check_compatibility(package.manifest())?;
        gate(package.manifest())?;
        let directory = package::stage(
            &self.config.store_directory,
            &package,
            self.target,
            matches!(source, PackageSource::Catalog(_)),
            fetch,
        )?;
        Ok(StagedPackage {
            directory,
            manifest: package.manifest().clone(),
            archive_sha256: package.archive_sha256().to_owned(),
            manifest_sha256: package.manifest_sha256().to_owned(),
            catalog_revision,
        })
    }

    fn signed_package<'a>(
        &self,
        document: &'a Value,
        app_id: &str,
        version: &str,
    ) -> io::Result<(rentnerproxy_app_contracts::Package<'a>, u64)> {
        let catalog = self
            .contracts
            .validate_catalog(document)
            .map_err(invalid_contract)?;
        let package = catalog
            .package(app_id, version, self.target)
            .ok_or_else(|| {
                invalid("App release is revoked, missing, or unavailable for this target")
            })?;
        Ok((package, catalog_revision(document)?))
    }

    fn check_compatibility(&self, manifest: &Value) -> io::Result<()> {
        let capabilities: Vec<_> = self
            .config
            .engine_capabilities
            .iter()
            .map(String::as_str)
            .collect();
        self.check_environment(
            manifest,
            &ManifestEnvironment {
                target: self.target,
                runtime_profile: RUNTIME_PROFILE,
                platform_api: PROTOCOL_VERSION,
                app_protocol: PROTOCOL_VERSION,
                ui_bridge: Some(PROTOCOL_VERSION),
                engine_capabilities: &capabilities,
            },
        )
    }

    /// Whether a platform offering `environment` can run the package described by `manifest`.
    fn check_environment(
        &self,
        manifest: &Value,
        environment: &ManifestEnvironment<'_>,
    ) -> io::Result<()> {
        self.contracts
            .check_manifest_compatibility(manifest, environment)
            .map_err(invalid_contract)?;
        if declares_engine_providers(manifest, environment) {
            Ok(())
        } else {
            Err(invalid_contract(ContractError::IncompatibleManifest))
        }
    }
}

/// Provider profiles whose results change the native proxy engine, with the engine capability
/// that applies them. The official profiles pair them, but the manifest contract does not require
/// it. A provider without its capability would pass every compatibility check, including the
/// upgrade preflight, and then meet an engine that cannot apply or enforce its contributions.
const ENGINE_PROVIDERS: [(&str, &str); 2] = [
    ("load-balancer", "caddy.load-balancing.v1"),
    ("crowdsec", "caddy.crowdsec.v1"),
];

/// Every engine provider the manifest declares also requires its engine capability, and the
/// environment offers it.
fn declares_engine_providers(manifest: &Value, environment: &ManifestEnvironment<'_>) -> bool {
    fn strings(value: &Value) -> impl Iterator<Item = &str> {
        value
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
    }
    strings(&manifest["providers"]).all(|profile| {
        ENGINE_PROVIDERS
            .iter()
            .filter(|(provider, _)| *provider == profile)
            .all(|(_, capability)| {
                strings(&manifest["requires"]["engineCapabilities"]).any(|name| name == *capability)
                    && environment.engine_capabilities.contains(capability)
            })
    })
}

fn catalog_revision(document: &Value) -> io::Result<u64> {
    document["revision"]
        .as_f64()
        .map(|revision| revision as u64)
        .ok_or_else(|| invalid("Missing catalog revision"))
}

/// Tell a catalog outage from a full network outage. `package_answers` probes the package
/// source and returns `None` when no listed release names one.
fn catalog_outage(error: io::Error, package_answers: impl FnOnce() -> Option<bool>) -> io::Error {
    if transport::unreachable_source(&error) != Some(transport::Source::Catalog) {
        return error;
    }
    match package_answers() {
        Some(false) => transport::SourceUnavailable::error(transport::Source::Network, error),
        _ => error,
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
