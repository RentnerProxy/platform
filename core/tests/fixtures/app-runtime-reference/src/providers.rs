use std::net::SocketAddr;

use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Default)]
pub struct Providers {
    discovered_port: Option<u16>,
    applied_contribution: Option<EngineContribution>,
    challenge_present: bool,
    crowdsec_block_cached: bool,
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "camelCase", deny_unknown_fields)]
pub enum ProviderRequest {
    Monitor {
        limit: usize,
    },
    DiscoveryRead {
        host: DiscoveryHost,
    },
    DiscoveryUpsert {
        host: DiscoveryHost,
        port: u16,
    },
    EngineRead,
    EngineApply {
        availability: Availability,
        contribution: EngineContribution,
    },
    DnsPresent,
    DnsCheck {
        observation: DnsObservation,
    },
    DnsCleanup {
        availability: Availability,
    },
    OidcProject {
        proof: FixtureProof,
    },
    CrowdSecEnforce {
        signal: CrowdSecSignal,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DiscoveryHost {
    Discovered,
    Manual,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Availability {
    Available,
    Unavailable,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EngineContribution {
    revision: u32,
    policy: BalancePolicy,
    upstreams: Vec<SocketAddr>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
enum BalancePolicy {
    RoundRobin,
    LeastConnections,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DnsObservation {
    Resolved,
    Missing,
    Unavailable,
}

// Controlled outcomes from a synthetic verifier. The fixture has no token handling.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FixtureProof {
    Verified,
    Invalid,
    Unavailable,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CrowdSecSignal {
    Allow,
    Deny,
    Unavailable,
}

impl Providers {
    pub fn call(&mut self, request: ProviderRequest) -> (StatusCode, Value) {
        match request {
            ProviderRequest::Monitor { limit } if (1..=2).contains(&limit) => {
                let samples = [
                    json!({"service": "proxy", "healthy": true}),
                    json!({"service": "controller", "healthy": true}),
                ];
                (StatusCode::OK, json!({"samples": &samples[..limit]}))
            }
            ProviderRequest::Monitor { .. } => error(StatusCode::BAD_REQUEST, "invalidLimit"),
            ProviderRequest::DiscoveryRead { host } => {
                (StatusCode::OK, self.discovery_record(host))
            }
            ProviderRequest::DiscoveryUpsert {
                host: DiscoveryHost::Manual,
                ..
            } => error(StatusCode::FORBIDDEN, "foreignOwner"),
            ProviderRequest::DiscoveryUpsert {
                host: DiscoveryHost::Discovered,
                port,
            } => {
                if port == 0 {
                    return error(StatusCode::BAD_REQUEST, "invalidPort");
                }
                self.discovered_port = Some(port);
                (
                    StatusCode::OK,
                    self.discovery_record(DiscoveryHost::Discovered),
                )
            }
            ProviderRequest::EngineRead => (StatusCode::OK, self.engine_state()),
            ProviderRequest::EngineApply {
                availability: Availability::Unavailable,
                ..
            } => error(StatusCode::SERVICE_UNAVAILABLE, "engineUnavailable"),
            ProviderRequest::EngineApply { contribution, .. } => {
                let applied_revision = self
                    .applied_contribution
                    .as_ref()
                    .map_or(0, |applied| applied.revision);
                if contribution.revision <= applied_revision || contribution.upstreams.is_empty() {
                    return error(StatusCode::BAD_REQUEST, "invalidContribution");
                }
                self.applied_contribution = Some(contribution);
                (StatusCode::OK, self.engine_state())
            }
            ProviderRequest::DnsPresent => {
                self.challenge_present = true;
                self.dns_result(StatusCode::OK, "presented")
            }
            ProviderRequest::DnsCheck {
                observation: DnsObservation::Resolved,
            } if self.challenge_present => self.dns_result(StatusCode::OK, "verified"),
            ProviderRequest::DnsCheck {
                observation: DnsObservation::Unavailable,
            }
            | ProviderRequest::DnsCleanup {
                availability: Availability::Unavailable,
            } => self.dns_result(StatusCode::SERVICE_UNAVAILABLE, "providerUnavailable"),
            ProviderRequest::DnsCheck { .. } => {
                self.dns_result(StatusCode::CONFLICT, "challengeMissing")
            }
            ProviderRequest::DnsCleanup { .. } => {
                self.challenge_present = false;
                self.dns_result(StatusCode::OK, "cleanedUp")
            }
            ProviderRequest::OidcProject { proof } => match proof {
                FixtureProof::Verified => (
                    StatusCode::OK,
                    json!({"identity": {"subject": "fixture-user", "groups": ["fixture-users"]}}),
                ),
                FixtureProof::Invalid => error(StatusCode::UNAUTHORIZED, "invalidProof"),
                FixtureProof::Unavailable => {
                    error(StatusCode::SERVICE_UNAVAILABLE, "identityUnavailable")
                }
            },
            ProviderRequest::CrowdSecEnforce { signal } => {
                let (status, outcome) = match signal {
                    CrowdSecSignal::Allow => {
                        self.crowdsec_block_cached = false;
                        (StatusCode::OK, "allow")
                    }
                    CrowdSecSignal::Deny => {
                        self.crowdsec_block_cached = true;
                        (StatusCode::FORBIDDEN, "deny")
                    }
                    CrowdSecSignal::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
                };
                (
                    status,
                    json!({
                        "outcome": outcome,
                        "allowed": status == StatusCode::OK,
                        "cachedBlock": self.crowdsec_block_cached,
                    }),
                )
            }
        }
    }

    fn discovery_record(&self, host: DiscoveryHost) -> Value {
        match host {
            DiscoveryHost::Discovered => {
                json!({"host": "discovered.test", "owner": "docker-discovery", "port": self.discovered_port})
            }
            DiscoveryHost::Manual => {
                json!({"host": "manual.test", "owner": "operator", "port": 9000})
            }
        }
    }

    fn engine_state(&self) -> Value {
        json!({"appliedContribution": self.applied_contribution})
    }

    fn dns_result(&self, status: StatusCode, outcome: &str) -> (StatusCode, Value) {
        // The challenge provider can report DNS state. The serving certificate is fixture-owned.
        (
            status,
            json!({
                "outcome": outcome,
                "challengePresent": self.challenge_present,
                "servingCertificate": "fixture-cert-1",
            }),
        )
    }
}

fn error(status: StatusCode, code: &str) -> (StatusCode, Value) {
    (status, json!({ "error": code }))
}
