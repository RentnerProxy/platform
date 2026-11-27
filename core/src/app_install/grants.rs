//! The grants an app release requests and the Owner's decision about them.
//!
//! A signed manifest declares capabilities, provider profiles and permission keys, never grants.
//! The platform derives the requested set from it, and the Owner supplies the resources. These
//! functions are pure: the app manager stores the decided set with the release in its journal and
//! publishes it to the web authority, which checks every app call against it.

use std::{collections::BTreeSet, fmt, io};

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg(test)]
#[path = "../../tests/private/app_install/grants.rs"]
mod tests;

/// The most grants one approval holds.
pub(crate) const MAX_GRANTS: usize = 128;

const INSTALLATION: &str = "installation";
const PROVIDER_PROFILES: &str = "providerProfiles";
const PROXY_HOSTS: &str = "proxyHosts";
/// Every platform proxy host, including hosts created after the approval. Only the Owner chooses
/// it, in place of selected hosts, and only for capabilities that read or probe hosts.
const ALL_PROXY_HOSTS: &str = "allProxyHosts";
/// The resource of an `allProxyHosts` grant.
const ALL_HOSTS: &str = "all";
const DYNAMIC_HOST_CAPABILITIES: [&str; 2] =
    ["proxy.hosts.read.v1", "diagnostics.upstream.probe.v1"];

/// Capabilities with a working platform endpoint. The other contract capabilities have none yet,
/// and owned proxy hosts wait for their own approval flow, so a release that requests one of them
/// cannot be approved on this appliance.
const APPROVABLE: [(&str, &str); 3] = [
    ("proxy.hosts.read.v1", PROXY_HOSTS),
    ("diagnostics.upstream.probe.v1", PROXY_HOSTS),
    ("notifications.publish.v1", INSTALLATION),
];
const PROVIDER: (&str, &str) = ("app.provider.register", PROVIDER_PROFILES);
/// Support grants that an app with any capability needs for change events and its audit trail.
const SUPPORT: [(&str, &str); 2] = [
    ("app.events.subscribe", INSTALLATION),
    ("app.audit.record", INSTALLATION),
];
/// Only root grants secret reads, with the control CLI. Releases never request them.
const SECRET: (&str, &str) = ("app.secret.read", "secretReferences");
const PROFILES: [&str; 6] = [
    "monitoring",
    "docker-discovery",
    "load-balancer",
    "dns",
    "oidc",
    "crowdsec",
];

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Capability {
    pub id: String,
    pub scope: String,
}

impl Capability {
    fn is(&self, (id, scope): (&str, &str)) -> bool {
        self.id == id && self.scope == scope
    }
}

/// One grant as the web authority enforces it.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Grant {
    pub capability: Capability,
    pub resource_id: String,
    pub allow_service: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_key: Option<String>,
}

/// One grant a release requests. A selectable scope has no resource: the Owner picks at least
/// one. The core fills the installation itself.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[cfg_attr(test, derive(Deserialize))]
#[serde(rename_all = "camelCase")]
pub(crate) struct RequestedGrant {
    pub capability: Capability,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<String>,
    pub allow_service: bool,
}

/// One grant the Owner approved for a requested capability.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[cfg_attr(test, derive(Serialize))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ApprovedGrant {
    pub capability: Capability,
    #[serde(default)]
    pub resource_id: Option<String>,
    pub allow_service: bool,
    #[serde(default)]
    pub permission_key: Option<String>,
}

/// The release requests a capability that this appliance cannot grant.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Unapprovable;

/// The release needs an approval of exactly the grants it requests.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ApprovalRequired;

impl fmt::Display for ApprovalRequired {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Release requires an approval of exactly the grants it requests")
    }
}

impl std::error::Error for ApprovalRequired {}

impl From<ApprovalRequired> for io::Error {
    fn from(error: ApprovalRequired) -> Self {
        io::Error::new(io::ErrorKind::PermissionDenied, error)
    }
}

/// Whether `error` refused a release for a missing or mismatched approval.
pub(crate) fn approval_required(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|cause| cause.is::<ApprovalRequired>())
}

/// The grants that `manifest` requests. Fails when one of them cannot be approved.
pub(crate) fn requested(manifest: &Value) -> Result<Vec<RequestedGrant>, Unapprovable> {
    match derive(manifest) {
        (items, true) => Ok(items),
        (_, false) => Err(Unapprovable),
    }
}

/// The app-owned permission keys a grant may name.
pub(crate) fn permission_keys(manifest: &Value) -> Vec<String> {
    manifest["permissions"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

/// Every approvable item the manifest requests, and whether nothing else is requested.
fn derive(manifest: &Value) -> (Vec<RequestedGrant>, bool) {
    let (Some(capabilities), Some(providers)) = (
        manifest["capabilities"].as_array(),
        manifest["providers"].as_array(),
    ) else {
        return (Vec::new(), false);
    };
    let mut approvable = true;
    let mut items = Vec::new();
    let mut add = |(id, scope): (&str, &str), resource_id: Option<&str>| {
        let item = RequestedGrant {
            capability: Capability {
                id: id.to_owned(),
                scope: scope.to_owned(),
            },
            resource_id: resource_id.map(str::to_owned),
            allow_service: true,
        };
        if !items.contains(&item) {
            items.push(item);
        }
    };
    for capability in capabilities {
        match (capability["id"].as_str(), capability["scope"].as_str()) {
            (Some(id), Some(scope)) if APPROVABLE.contains(&(id, scope)) => add((id, scope), None),
            _ => approvable = false,
        }
    }
    for profile in providers {
        match profile.as_str() {
            Some(profile) if PROFILES.contains(&profile) => add(PROVIDER, Some(profile)),
            _ => approvable = false,
        }
    }
    if !capabilities.is_empty() {
        for support in SUPPORT {
            add(support, None);
        }
    }
    (items, approvable)
}

/// Accept `approval` only if it grants exactly what the release requests: no item it does not
/// request, every requested item covered, resources the Owner may choose, no wider service access
/// and only declared permission keys. Returns the grants in a stable order.
pub(crate) fn decide(
    requested: &[RequestedGrant],
    permission_keys: &[String],
    approval: &[ApprovedGrant],
    installation_id: &str,
) -> Result<Vec<Grant>, ApprovalRequired> {
    if approval.len() > MAX_GRANTS {
        return Err(ApprovalRequired);
    }
    let mut grants = approval
        .iter()
        .map(|item| {
            let resource_id = match (item.capability.scope.as_str(), &item.resource_id) {
                (INSTALLATION, None) => installation_id.to_owned(),
                (_, Some(resource_id)) => resource_id.clone(),
                (_, None) => return Err(ApprovalRequired),
            };
            Ok(Grant {
                capability: item.capability.clone(),
                resource_id,
                allow_service: item.allow_service,
                permission_key: item.permission_key.clone(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut targets = BTreeSet::new();
    let exact = grants.iter().all(|grant| {
        targets.insert((&grant.capability, &grant.resource_id))
            && declared_key(grant, permission_keys)
            && requested
                .iter()
                .any(|request| serves(request, grant, installation_id))
    }) && covered(requested, &grants, installation_id)
        && !mixes_host_scopes(&grants);
    if !exact {
        return Err(ApprovalRequired);
    }
    grants.sort();
    Ok(grants)
}

/// Carry the `approved` grants to a release that requests `requested`, or `None` when that
/// release needs a new approval. Keeps the grants whose capability, scope and fixed resource the
/// release still requests, and root's secret reads. A new capability, a changed scope, a new
/// provider profile or a dropped permission key that a kept grant names needs a new approval.
pub(crate) fn carry(
    approved: &[Grant],
    requested: &[RequestedGrant],
    permission_keys: &[String],
    installation_id: &str,
) -> Option<Vec<Grant>> {
    let kept: Vec<_> = approved
        .iter()
        .filter(|grant| {
            grant.capability.is(SECRET)
                || requested
                    .iter()
                    .any(|request| serves(request, grant, installation_id))
        })
        .cloned()
        .collect();
    (kept
        .iter()
        .all(|grant| declared_key(grant, permission_keys))
        && covered(requested, &kept, installation_id))
    .then_some(kept)
}

/// Carry `approved` like [`carry`], and narrow the result to the release's own `stored`
/// approval when the installation already holds one: a carried grant never restores what the
/// Owner's latest decision for that exact release left out.
pub(crate) fn carry_to(
    approved: &[Grant],
    stored: Option<&[Grant]>,
    requested: &[RequestedGrant],
    permission_keys: &[String],
    installation_id: &str,
) -> Option<Vec<Grant>> {
    let kept = carry(approved, requested, permission_keys, installation_id)?;
    let Some(stored) = stored else {
        return Some(kept);
    };
    let narrowed = narrow(kept, requested, stored, installation_id);
    // The stored permission key may be one the target no longer declares.
    (narrowed
        .iter()
        .all(|grant| declared_key(grant, permission_keys))
        && covered(requested, &narrowed, installation_id))
    .then_some(narrowed)
}

/// Keep a grant the release requests only if `stored` holds the same capability and resource,
/// with the narrower service access and the stored permission key.
fn narrow(
    grants: Vec<Grant>,
    requested: &[RequestedGrant],
    stored: &[Grant],
    installation_id: &str,
) -> Vec<Grant> {
    grants
        .into_iter()
        .filter_map(|grant| {
            if !decides(requested, &grant, installation_id) {
                return Some(grant);
            }
            let own = stored.iter().find(|own| {
                own.capability == grant.capability && own.resource_id == grant.resource_id
            })?;
            Some(Grant {
                allow_service: grant.allow_service && own.allow_service,
                permission_key: own.permission_key.clone().or(grant.permission_key),
                ..grant
            })
        })
        .collect()
}

/// Apply the Owner's explicit decision for one release to the stored approval of another release
/// of the same installation, so that a rollback or a later update never widens it again. For
/// every capability the decided release requests, a grant whose capability and resource the
/// decision no longer contains is removed, and a kept grant takes the decision's service access
/// and permission key. Grants the decision could not cover, such as another provider profile or
/// a secret read, stay as they are.
pub(crate) fn apply_decision(
    grants: &mut Vec<Grant>,
    requested: &[RequestedGrant],
    decided: &[Grant],
    installation_id: &str,
) {
    grants.retain_mut(|grant| {
        if !decides(requested, grant, installation_id) {
            return true;
        }
        match decided.iter().find(|decided| {
            decided.capability == grant.capability && decided.resource_id == grant.resource_id
        }) {
            Some(decided) => {
                grant.allow_service = decided.allow_service;
                grant.permission_key.clone_from(&decided.permission_key);
                true
            }
            None => false,
        }
    });
}

/// What staging decided for a release.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Decision {
    /// The grants the release receives, in a stable order.
    pub grants: Vec<Grant>,
    /// Whether the Owner approved `grants` explicitly. Once the release activates, an explicit
    /// decision also applies to every other stored approval of the installation.
    pub explicit: bool,
}

/// Whether the Owner's `approval` decides exactly the `approved` grants of a release, with the
/// installation resource filled in and root's secret reads kept, as [`approve`] would decide it.
pub(crate) fn same_decision(
    approval: &[ApprovedGrant],
    approved: &[Grant],
    installation_id: &str,
) -> bool {
    let Some(mut decided) = approval
        .iter()
        .map(|item| {
            let resource_id = match (item.capability.scope.as_str(), &item.resource_id) {
                (INSTALLATION, None) => installation_id.to_owned(),
                (_, Some(resource_id)) => resource_id.clone(),
                (_, None) => return None,
            };
            Some(Grant {
                capability: item.capability.clone(),
                resource_id,
                allow_service: item.allow_service,
                permission_key: item.permission_key.clone(),
            })
        })
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };
    decided.extend(
        approved
            .iter()
            .filter(|grant| grant.capability.is(SECRET))
            .cloned(),
    );
    decided.sort();
    let mut approved = approved.to_vec();
    approved.sort();
    decided == approved
}

/// Decide the grants that a release with the signed `manifest` receives: exactly the Owner's
/// `approval` when there is one, otherwise the `carried` approval if it still covers the
/// release, narrowed to the release's own `stored` approval. Root's secret reads in `carried`
/// survive either way, as long as the release still declares their permission key.
pub(crate) fn approve(
    manifest: &Value,
    approval: Option<&[ApprovedGrant]>,
    carried: &[Grant],
    stored: Option<&[Grant]>,
    installation_id: &str,
) -> Result<Decision, ApprovalRequired> {
    let requested = requested(manifest).map_err(|Unapprovable| ApprovalRequired)?;
    let keys = permission_keys(manifest);
    let Some(approval) = approval else {
        let mut grants = carry_to(carried, stored, &requested, &keys, installation_id)
            .ok_or(ApprovalRequired)?;
        grants.sort();
        return Ok(Decision {
            grants,
            explicit: false,
        });
    };
    let mut grants = decide(&requested, &keys, approval, installation_id)?;
    grants.extend(
        carried
            .iter()
            .filter(|grant| grant.capability.is(SECRET) && declared_key(grant, &keys))
            .cloned(),
    );
    if grants.len() > MAX_GRANTS {
        return Err(ApprovalRequired);
    }
    grants.sort();
    Ok(Decision {
        grants,
        explicit: true,
    })
}

/// Whether `grants` stay within what `manifest` requests, as root's control CLI and every launch
/// require. Root may approve a subset, and secret reads that no release requests.
pub(crate) fn within(manifest: &Value, grants: &[Grant], installation_id: &str) -> bool {
    let (items, _) = derive(manifest);
    let keys = permission_keys(manifest);
    let mut targets = BTreeSet::new();
    grants.len() <= MAX_GRANTS
        && grants.iter().all(|grant| {
            targets.insert((&grant.capability, &grant.resource_id))
                && declared_key(grant, &keys)
                && ((grant.capability.is(SECRET) && record_id(&grant.resource_id))
                    || items
                        .iter()
                        .any(|request| serves(request, grant, installation_id)))
        })
}

/// Whether an approved `scope` covers the scope a release requests. All proxy hosts cover
/// selected proxy hosts; every other scope covers only itself.
fn covers(approved: &str, requested: &str) -> bool {
    approved == requested || (approved == ALL_PROXY_HOSTS && requested == PROXY_HOSTS)
}

/// Whether one capability is approved both for all proxy hosts and for selected ones, which
/// would make the selection meaningless.
fn mixes_host_scopes(grants: &[Grant]) -> bool {
    grants.iter().any(|all| {
        all.capability.scope == ALL_PROXY_HOSTS
            && grants.iter().any(|selected| {
                selected.capability.scope == PROXY_HOSTS
                    && selected.capability.id == all.capability.id
            })
    })
}

/// Whether a decision about the requested items covers `grant`: the release requests its
/// capability in a scope it covers, and the grant's resource is one the Owner chose for it.
fn decides(requested: &[RequestedGrant], grant: &Grant, installation_id: &str) -> bool {
    requested
        .iter()
        .any(|request| serves(request, grant, installation_id))
}

/// Whether `grant` serves the requested item: the same capability in a scope it covers, a
/// resource the item allows, and no service access the item does not request.
fn serves(request: &RequestedGrant, grant: &Grant, installation_id: &str) -> bool {
    request.capability.id == grant.capability.id
        && covers(&grant.capability.scope, &request.capability.scope)
        && (request.allow_service || !grant.allow_service)
        && match (
            request.capability.scope.as_str(),
            grant.capability.scope.as_str(),
        ) {
            (INSTALLATION, _) => grant.resource_id == installation_id,
            (PROVIDER_PROFILES, _) => request.resource_id.as_ref() == Some(&grant.resource_id),
            (PROXY_HOSTS, ALL_PROXY_HOSTS) => {
                DYNAMIC_HOST_CAPABILITIES.contains(&grant.capability.id.as_str())
                    && grant.resource_id == ALL_HOSTS
            }
            (PROXY_HOSTS, _) => platform_host_id(&grant.resource_id),
            _ => false,
        }
}

/// Whether every requested item has a grant. A selectable scope needs at least one resource.
fn covered(requested: &[RequestedGrant], grants: &[Grant], installation_id: &str) -> bool {
    requested.iter().all(|request| {
        grants
            .iter()
            .any(|grant| serves(request, grant, installation_id))
    })
}

fn declared_key(grant: &Grant, permission_keys: &[String]) -> bool {
    grant
        .permission_key
        .as_ref()
        .is_none_or(|key| permission_keys.contains(key))
}

/// A lowercase RFC 9562 UUID, as the platform names proxy hosts.
fn platform_host_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    let hex = |range: std::ops::Range<usize>| {
        bytes[range]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    };
    bytes.len() == 36
        && [8, 13, 18, 23].iter().all(|&dash| bytes[dash] == b'-')
        && hex(0..8)
        && hex(9..13)
        && hex(14..18)
        && hex(19..23)
        && hex(24..36)
        && (value == "00000000-0000-0000-0000-000000000000"
            || value == "ffffffff-ffff-ffff-ffff-ffffffffffff"
            || ((b'1'..=b'8').contains(&bytes[14])
                && matches!(bytes[19], b'8' | b'9' | b'a' | b'b')))
}

/// An app record ID, as the web authority accepts it for a grant's resource.
fn record_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}
