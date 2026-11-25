use std::{collections::BTreeSet, io};

use marketplace_artifacts::parse_json;
use rentnerproxy_app_contracts::ManifestEnvironment;
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{Installer, invalid_contract};

const MAX_ENGINE_CAPABILITIES: usize = 16;
const MAX_NAME_BYTES: usize = 64;
const MAX_VERSION_BYTES: usize = 32;

/// The app runtime a target platform release declares in its release requirements asset.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct TargetEnvironment {
    runtime_profile: String,
    platform_api: String,
    app_protocol: String,
    ui_bridge: Option<String>,
    engine_capabilities: Vec<String>,
}

impl TargetEnvironment {
    /// Bound every field. A target may offer engine capabilities this release does not know yet.
    pub(crate) fn valid(&self) -> bool {
        name(&self.runtime_profile, false)
            && [&self.platform_api, &self.app_protocol]
                .into_iter()
                .chain(&self.ui_bridge)
                .all(|version| protocol_version(version))
            && self.engine_capabilities.len() <= MAX_ENGINE_CAPABILITIES
            && self
                .engine_capabilities
                .iter()
                .all(|capability| name(capability, true))
            && self
                .engine_capabilities
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                == self.engine_capabilities.len()
    }
}

fn name(value: &str, dotted: bool) -> bool {
    let mut parts = value.split('.');
    (1..=MAX_NAME_BYTES).contains(&value.len())
        && (!dotted || parts.clone().count() >= 2)
        && (dotted || !value.contains('.'))
        && parts.all(|part| {
            part.bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

fn protocol_version(value: &str) -> bool {
    value.len() <= MAX_VERSION_BYTES
        && Version::parse(value)
            .is_ok_and(|version| version.pre.is_empty() && version.build.is_empty())
}

/// An installed release as the app manager journal records it.
pub(crate) struct InstalledRelease<'a> {
    pub(crate) app_id: &'a str,
    pub(crate) version: &'a str,
    pub(crate) archive_sha256: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum TargetSupport {
    Compatible,
    Incompatible,
    /// The accepted catalog no longer describes this exact release.
    Unknown,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
pub(crate) struct TargetCheck {
    /// Provider profiles from the signed manifest; absent while the release is unknown.
    pub(crate) providers: Option<Vec<String>>,
    #[serde(rename = "target")]
    pub(crate) support: TargetSupport,
}

impl TargetCheck {
    const UNKNOWN: Self = Self {
        providers: None,
        support: TargetSupport::Unknown,
    };
}

pub(super) fn providers(manifest: &Value) -> Vec<String> {
    manifest["providers"]
        .as_array()
        .map(|profiles| {
            profiles
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

impl Installer {
    /// Check installed releases against a target platform before its image replaces this one.
    /// Manifests come from the accepted signed catalog, matched by the recorded archive digest, so
    /// the check never trusts the staged package tree or downloads anything.
    pub(crate) fn check_target(
        &self,
        environment: &TargetEnvironment,
        releases: &[InstalledRelease<'_>],
    ) -> io::Result<Vec<TargetCheck>> {
        let Some((_, trusted)) = self.checkpoint()? else {
            return Ok(releases.iter().map(|_| TargetCheck::UNKNOWN).collect());
        };
        let document = parse_json(trusted.catalog_bytes())?;
        let catalog = self
            .contracts
            .validate_catalog(&document)
            .map_err(invalid_contract)?;
        let capabilities: Vec<_> = environment
            .engine_capabilities
            .iter()
            .map(String::as_str)
            .collect();
        let target = ManifestEnvironment {
            target: self.target,
            runtime_profile: &environment.runtime_profile,
            platform_api: &environment.platform_api,
            app_protocol: &environment.app_protocol,
            ui_bridge: environment.ui_bridge.as_deref(),
            engine_capabilities: &capabilities,
        };
        Ok(releases
            .iter()
            .map(|release| {
                catalog
                    .package(release.app_id, release.version, self.target)
                    .filter(|package| package.archive_sha256() == release.archive_sha256)
                    .map_or(TargetCheck::UNKNOWN, |package| TargetCheck {
                        providers: Some(providers(package.manifest())),
                        support: if self.check_environment(package.manifest(), &target).is_ok() {
                            TargetSupport::Compatible
                        } else {
                            TargetSupport::Incompatible
                        },
                    })
            })
            .collect())
    }
}
