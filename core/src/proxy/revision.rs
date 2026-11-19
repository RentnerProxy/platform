use crate::models::{DefaultSite, ProxyHost, ProxyHttpSettings, RedirectHost, TrustedCa};
use aws_lc_rs::digest::{SHA256, digest};
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::LazyLock;

pub(super) static SNAPSHOT_LAYOUT: LazyLock<SnapshotLayout> = LazyLock::new(|| {
    serde_json::from_str(include_str!("snapshot-layout.json"))
        .expect("invalid proxy snapshot layout")
});

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
enum SnapshotField {
    Version,
    ProxyHosts,
    RedirectHosts,
    HttpSettings,
    TrustedCas,
    DefaultSite,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SnapshotVersions {
    pub(super) base: u8,
    pub(super) upstream_pool: u8,
    pub(super) failover: u8,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SnapshotLayout {
    pub(super) versions: SnapshotVersions,
    fields: [SnapshotField; 6],
}

struct CanonicalSnapshot<'a> {
    version: u8,
    proxy_hosts: &'a [ProxyHost],
    redirect_hosts: &'a [RedirectHost],
    http_settings: &'a ProxyHttpSettings,
    trusted_cas: &'a [TrustedCa],
    default_site: &'a DefaultSite,
}

impl Serialize for CanonicalSnapshot<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let default_site = !self.default_site.is_default();
        let mut map = serializer.serialize_map(Some(
            SNAPSHOT_LAYOUT.fields.len() - usize::from(!default_site),
        ))?;
        for field in &SNAPSHOT_LAYOUT.fields {
            match field {
                SnapshotField::Version => map.serialize_entry("version", &self.version)?,
                SnapshotField::ProxyHosts => map.serialize_entry("proxyHosts", self.proxy_hosts)?,
                SnapshotField::RedirectHosts => {
                    map.serialize_entry("redirectHosts", self.redirect_hosts)?;
                }
                SnapshotField::HttpSettings => {
                    map.serialize_entry("httpSettings", self.http_settings)?;
                }
                SnapshotField::TrustedCas => map.serialize_entry("trustedCas", self.trusted_cas)?,
                SnapshotField::DefaultSite if default_site => {
                    map.serialize_entry("defaultSite", self.default_site)?;
                }
                SnapshotField::DefaultSite => {}
            }
        }
        map.end()
    }
}

#[cfg(test)]
pub(crate) fn revision_for_hosts(hosts: &[ProxyHost]) -> String {
    revision_for_configuration_with_redirects(hosts, &[], &ProxyHttpSettings::default(), &[])
}

#[cfg(test)]
pub(crate) fn revision_for_configuration(
    hosts: &[ProxyHost],
    http_settings: &ProxyHttpSettings,
) -> String {
    revision_for_configuration_with_redirects(hosts, &[], http_settings, &[])
}

#[cfg(test)]
pub(crate) fn revision_for_configuration_with_trusted_cas(
    hosts: &[ProxyHost],
    http_settings: &ProxyHttpSettings,
    trusted_cas: &[TrustedCa],
) -> String {
    revision_for_configuration_with_redirects(hosts, &[], http_settings, trusted_cas)
}

#[cfg(test)]
pub(crate) fn revision_for_configuration_with_redirects(
    hosts: &[ProxyHost],
    redirect_hosts: &[RedirectHost],
    http_settings: &ProxyHttpSettings,
    trusted_cas: &[TrustedCa],
) -> String {
    revision_for_full_configuration(
        hosts,
        redirect_hosts,
        http_settings,
        trusted_cas,
        &DefaultSite::default(),
    )
}

/// Hashes the canonical versioned configuration without sorting a pool's ordered member list.
#[cfg(test)]
pub(crate) fn revision_for_full_configuration(
    hosts: &[ProxyHost],
    redirect_hosts: &[RedirectHost],
    http_settings: &ProxyHttpSettings,
    trusted_cas: &[TrustedCa],
    default_site: &DefaultSite,
) -> String {
    let mut hosts = hosts.to_vec();
    let mut redirect_hosts = redirect_hosts.to_vec();
    let mut trusted_cas = trusted_cas.to_vec();
    canonicalize_configuration(&mut hosts, &mut redirect_hosts, &mut trusted_cas);
    revision_for_canonical_configuration(
        &hosts,
        &redirect_hosts,
        http_settings,
        &trusted_cas,
        default_site,
    )
}

/// Hashes collections already sorted by `canonicalize_configuration` without copying them.
pub(super) fn revision_for_canonical_configuration(
    hosts: &[ProxyHost],
    redirect_hosts: &[RedirectHost],
    http_settings: &ProxyHttpSettings,
    trusted_cas: &[TrustedCa],
    default_site: &DefaultSite,
) -> String {
    hash_snapshot(&CanonicalSnapshot {
        version: super::configuration_version(hosts),
        proxy_hosts: hosts,
        redirect_hosts,
        http_settings,
        trusted_cas,
        default_site,
    })
}

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hash_snapshot(snapshot: &impl Serialize) -> String {
    let bytes = serde_json::to_vec(snapshot)
        .expect("canonical proxy snapshot only contains serializable strings and numbers");
    let digest = digest(&SHA256, &bytes);
    format!("sha256:{}", hex_digest(digest.as_ref()))
}

pub(crate) fn revision_from_config(contents: &str) -> Option<String> {
    let config = serde_json::from_str::<ProbeConfig>(contents).ok()?;
    config
        .apps?
        .http?
        .servers
        .get("rentnerproxy-probe")
        .and_then(|server| find_revision(&server.routes))
}

fn find_revision(routes: &[ProbeRoute]) -> Option<String> {
    for route in routes {
        if !route.terminal
            || route.matchers.len() != 1
            || route.matchers[0].path != ["/__rentnerproxy_runtime_probe"]
        {
            continue;
        }
        for handler in &route.handle {
            if handler.handler != "static_response" || handler.status_code != Some(200) {
                continue;
            }
            if let Some(revision) = handler
                .body
                .as_deref()
                .and_then(|body| body.strip_suffix('\n'))
                .filter(|revision| is_revision(revision))
            {
                return Some(revision.to_owned());
            }
        }
    }
    None
}

pub(super) fn canonicalize_configuration(
    hosts: &mut [ProxyHost],
    redirect_hosts: &mut [RedirectHost],
    trusted_cas: &mut [TrustedCa],
) {
    for host in hosts.iter_mut() {
        host.domains.sort_unstable();
    }
    hosts.sort_unstable_by(|left, right| left.id.cmp(&right.id));
    for host in redirect_hosts.iter_mut() {
        host.domains.sort_unstable();
    }
    redirect_hosts.sort_unstable_by(|left, right| left.id.cmp(&right.id));
    trusted_cas.sort_unstable_by(|left, right| left.id.cmp(&right.id));
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProbeConfig {
    apps: Option<ProbeApps>,
}

#[derive(Deserialize)]
struct ProbeApps {
    http: Option<ProbeHttp>,
}

#[derive(Deserialize)]
struct ProbeHttp {
    #[serde(default)]
    servers: BTreeMap<String, ProbeServer>,
}

#[derive(Deserialize)]
struct ProbeServer {
    #[serde(default)]
    routes: Vec<ProbeRoute>,
}

#[derive(Deserialize)]
struct ProbeRoute {
    #[serde(default, rename = "match")]
    matchers: Vec<ProbeMatcher>,
    #[serde(default)]
    terminal: bool,
    #[serde(default)]
    handle: Vec<ProbeHandler>,
}

#[derive(Deserialize)]
struct ProbeMatcher {
    #[serde(default)]
    path: Vec<String>,
}

#[derive(Deserialize)]
struct ProbeHandler {
    handler: String,
    body: Option<String>,
    status_code: Option<u16>,
}

pub(crate) fn is_revision(value: &str) -> bool {
    let Some(hash) = value.strip_prefix("sha256:") else {
        return false;
    };
    hash.len() == 64
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
