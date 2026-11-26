use super::*;
use serde_json::json;

const ID: &str = "app-fixture";
const HOST: &str = "0b6f3c0e-8d1a-4f43-9c2e-1d7a5b9e4f21";
const OTHER_HOST: &str = "5c1e2f3a-4b5d-4e6f-8a7b-9c0d1e2f3a4b";

fn capability(id: &str, scope: &str) -> Capability {
    Capability {
        id: id.into(),
        scope: scope.into(),
    }
}

fn manifest(capabilities: Value, providers: Value) -> Value {
    json!({
        "capabilities": capabilities,
        "providers": providers,
        "permissions": ["view", "manage"],
    })
}

fn monitoring() -> Value {
    manifest(
        json!([
            {"id": "proxy.hosts.read.v1", "scope": "proxyHosts"},
            {"id": "notifications.publish.v1", "scope": "installation"},
        ]),
        json!(["monitoring", "dns"]),
    )
}

fn item(id: &str, scope: &str, resource_id: Option<&str>) -> RequestedGrant {
    RequestedGrant {
        capability: capability(id, scope),
        resource_id: resource_id.map(Into::into),
        allow_service: true,
    }
}

fn approved(id: &str, scope: &str, resource_id: Option<&str>) -> ApprovedGrant {
    ApprovedGrant {
        capability: capability(id, scope),
        resource_id: resource_id.map(Into::into),
        allow_service: true,
        permission_key: None,
    }
}

fn grant(id: &str, scope: &str, resource_id: &str) -> Grant {
    Grant {
        capability: capability(id, scope),
        resource_id: resource_id.into(),
        allow_service: true,
        permission_key: None,
    }
}

/// An approval of everything `monitoring()` requests, with one proxy host.
fn full_approval() -> Vec<ApprovedGrant> {
    vec![
        approved("proxy.hosts.read.v1", "proxyHosts", Some(HOST)),
        approved("notifications.publish.v1", "installation", None),
        approved(
            "app.provider.register",
            "providerProfiles",
            Some("monitoring"),
        ),
        approved("app.provider.register", "providerProfiles", Some("dns")),
        approved("app.events.subscribe", "installation", None),
        approved("app.audit.record", "installation", None),
    ]
}

fn keys() -> Vec<String> {
    vec!["view".into(), "manage".into()]
}

#[test]
fn requested_grants_derive_from_capabilities_and_provider_profiles() {
    assert_eq!(
        requested(&monitoring()).unwrap(),
        [
            item("proxy.hosts.read.v1", "proxyHosts", None),
            item("notifications.publish.v1", "installation", None),
            item(
                "app.provider.register",
                "providerProfiles",
                Some("monitoring")
            ),
            item("app.provider.register", "providerProfiles", Some("dns")),
            item("app.events.subscribe", "installation", None),
            item("app.audit.record", "installation", None),
        ]
    );
    assert_eq!(
        serde_json::to_value(requested(&monitoring()).unwrap()).unwrap()[2],
        json!({
            "capability": {"id": "app.provider.register", "scope": "providerProfiles"},
            "resourceId": "monitoring",
            "allowService": true,
        })
    );
    assert_eq!(
        serde_json::to_value(requested(&monitoring()).unwrap()).unwrap()[0],
        json!({"capability": {"id": "proxy.hosts.read.v1", "scope": "proxyHosts"}, "allowService": true})
    );
    // Without capabilities, neither events nor an audit trail is requested.
    assert_eq!(requested(&manifest(json!([]), json!([]))).unwrap(), []);
    assert_eq!(
        requested(&manifest(json!([]), json!(["oidc"]))).unwrap(),
        [item(
            "app.provider.register",
            "providerProfiles",
            Some("oidc")
        )]
    );
    let probe = manifest(
        json!([{"id": "diagnostics.upstream.probe.v1", "scope": "proxyHosts"}]),
        json!([]),
    );
    assert_eq!(requested(&probe).unwrap().len(), 3);
    // Secret reads are never requested.
    assert!(
        requested(&monitoring())
            .unwrap()
            .iter()
            .all(|item| item.capability.id != "app.secret.read")
    );
    assert_eq!(permission_keys(&monitoring()), keys());
}

#[test]
fn capabilities_without_an_approval_flow_cannot_be_approved() {
    for (id, scope) in [
        ("proxy.hosts.manage-owned.v1", "ownedProxyHosts"),
        ("docker.inventory.observe.v1", "dockerConnections"),
        ("dns.challenge.manage.v1", "dnsZones"),
        ("engine.contributions.submit.v1", "ownedEngineResources"),
        ("identity.provider.register.v1", "identityProviders"),
        ("access.logs.read.v1", "proxyHosts"),
        ("security.enforcement.contribute.v1", "ownedEngineResources"),
        ("app.secret.read", "secretReferences"),
        ("proxy.hosts.read.v1", "installation"),
    ] {
        let manifest = manifest(
            json!([
                {"id": "proxy.hosts.read.v1", "scope": "proxyHosts"},
                {"id": id, "scope": scope},
            ]),
            json!([]),
        );
        assert_eq!(requested(&manifest), Err(Unapprovable), "{id}");
        let approval = approve(&manifest, Some(&[]), &[], None, ID);
        assert_eq!(approval, Err(ApprovalRequired), "{id}");
    }
    assert_eq!(
        requested(&manifest(json!([]), json!(["unknown"]))),
        Err(Unapprovable)
    );
    assert_eq!(requested(&json!({"providers": []})), Err(Unapprovable));
    assert_eq!(requested(&json!({"capabilities": []})), Err(Unapprovable));
}

#[test]
fn an_exact_approval_is_accepted_with_installation_resources_filled_in() {
    let requested = requested(&monitoring()).unwrap();
    let mut approval = full_approval();
    approval.push(approved(
        "proxy.hosts.read.v1",
        "proxyHosts",
        Some(OTHER_HOST),
    ));
    // The installation may also be named explicitly.
    approval[1].resource_id = Some(ID.into());
    // Narrowing service access and naming a declared permission key are allowed.
    approval[0].allow_service = false;
    approval[0].permission_key = Some("view".into());
    let grants = decide(&requested, &keys(), &approval, ID).unwrap();
    assert_eq!(grants.len(), 7);
    let mut sorted = grants.clone();
    sorted.sort();
    assert_eq!(grants, sorted);
    let read = grants
        .iter()
        .find(|grant| grant.resource_id == HOST)
        .unwrap();
    assert!(!read.allow_service);
    assert_eq!(read.permission_key.as_deref(), Some("view"));
    for support in [
        "app.events.subscribe",
        "app.audit.record",
        "notifications.publish.v1",
    ] {
        assert!(
            grants
                .iter()
                .any(|grant| grant.capability.id == support && grant.resource_id == ID)
        );
    }
    assert_eq!(
        serde_json::to_value(read).unwrap(),
        json!({
            "capability": {"id": "proxy.hosts.read.v1", "scope": "proxyHosts"},
            "resourceId": HOST,
            "allowService": false,
            "permissionKey": "view",
        })
    );
    // A release that requests nothing accepts only an empty approval.
    assert_eq!(decide(&[], &[], &[], ID), Ok(Vec::new()));
    assert_eq!(
        decide(&[], &[], &full_approval()[..1], ID),
        Err(ApprovalRequired)
    );
}

#[test]
fn every_deviation_from_the_request_is_refused() {
    let requested = requested(&monitoring()).unwrap();
    let refuse = |change: &dyn Fn(&mut Vec<ApprovedGrant>)| {
        let mut approval = full_approval();
        change(&mut approval);
        decide(&requested, &keys(), &approval, ID)
    };
    assert!(refuse(&|_| ()).is_ok());
    type Change = dyn Fn(&mut Vec<ApprovedGrant>);
    let refusals: [(&str, &Change); 17] = [
        ("too many grants", &|approval| {
            approval
                .extend((0..MAX_GRANTS).map(|_| approved("app.audit.record", "installation", None)))
        }),
        ("duplicate host", &|approval| {
            approval.push(approved("proxy.hosts.read.v1", "proxyHosts", Some(HOST)))
        }),
        ("duplicate filled installation", &|approval| {
            approval.push(approved("app.audit.record", "installation", Some(ID)))
        }),
        ("unrequested capability", &|approval| {
            approval.push(approved(
                "diagnostics.upstream.probe.v1",
                "proxyHosts",
                Some(HOST),
            ))
        }),
        ("secret read", &|approval| {
            approval.push(approved(
                "app.secret.read",
                "secretReferences",
                Some("token"),
            ))
        }),
        ("other scope", &|approval| {
            approval[0].capability.scope = "ownedProxyHosts".into()
        }),
        ("other installation", &|approval| {
            approval[1].resource_id = Some("app-other".into())
        }),
        ("undeclared provider", &|approval| {
            approval[2].resource_id = Some("oidc".into())
        }),
        ("provider without profile", &|approval| {
            approval[2].resource_id = None
        }),
        ("host without resource", &|approval| {
            approval[0].resource_id = None
        }),
        ("uppercase host", &|approval| {
            approval[0].resource_id = Some(HOST.to_uppercase())
        }),
        ("host name instead of ID", &|approval| {
            approval[0].resource_id = Some("example.test".into())
        }),
        ("undeclared permission key", &|approval| {
            approval[0].permission_key = Some("admin".into())
        }),
        ("no host selected", &|approval| {
            approval.remove(0);
        }),
        ("provider profile omitted", &|approval| {
            approval.remove(3);
        }),
        ("audit omitted", &|approval| {
            approval.remove(5);
        }),
        ("unknown capability", &|approval| {
            approval.push(approved("example.unknown.v1", "proxyHosts", Some(HOST)))
        }),
    ];
    for (reason, change) in refusals {
        assert_eq!(refuse(change), Err(ApprovalRequired), "{reason}");
    }
    // Service access may only narrow.
    let narrow = [RequestedGrant {
        allow_service: false,
        ..item("notifications.publish.v1", "installation", None)
    }];
    let mut wider = approved("notifications.publish.v1", "installation", None);
    assert_eq!(
        decide(&narrow, &[], std::slice::from_ref(&wider), ID),
        Err(ApprovalRequired)
    );
    wider.allow_service = false;
    assert!(decide(&narrow, &[], &[wider], ID).is_ok());
}

#[test]
fn approved_grants_carry_only_to_releases_that_request_nothing_new() {
    let requested_now = requested(&monitoring()).unwrap();
    let mut approval = full_approval();
    approval[0].permission_key = Some("view".into());
    let approved = decide(&requested_now, &keys(), &approval, ID).unwrap();

    // The same request carries everything.
    assert_eq!(
        carry(&approved, &requested_now, &keys(), ID).as_deref(),
        Some(approved.as_slice())
    );
    // A release without notifications and the DNS profile keeps the rest.
    let fewer = manifest(
        json!([{"id": "proxy.hosts.read.v1", "scope": "proxyHosts"}]),
        json!(["monitoring"]),
    );
    let kept = carry(&approved, &requested(&fewer).unwrap(), &keys(), ID).unwrap();
    assert_eq!(kept.len(), 4);
    assert!(kept.iter().all(|grant| {
        grant.capability.id != "notifications.publish.v1" && grant.resource_id != "dns"
    }));
    // A new capability, a new provider profile or a changed scope needs a new approval.
    for wider in [
        manifest(
            json!([
                {"id": "proxy.hosts.read.v1", "scope": "proxyHosts"},
                {"id": "notifications.publish.v1", "scope": "installation"},
                {"id": "diagnostics.upstream.probe.v1", "scope": "proxyHosts"},
            ]),
            json!(["monitoring", "dns"]),
        ),
        manifest(
            json!([
                {"id": "proxy.hosts.read.v1", "scope": "proxyHosts"},
                {"id": "notifications.publish.v1", "scope": "installation"},
            ]),
            json!(["monitoring", "dns", "oidc"]),
        ),
    ] {
        assert_eq!(
            carry(&approved, &requested(&wider).unwrap(), &keys(), ID),
            None
        );
    }
    let mut rescoped = requested_now.clone();
    rescoped[0].capability.scope = "ownedProxyHosts".into();
    assert_eq!(carry(&approved, &rescoped, &keys(), ID), None);
    // Dropping a permission key that a kept grant names needs a new approval.
    assert_eq!(
        carry(&approved, &requested_now, &["manage".into()], ID),
        None
    );
    // A key only a dropped grant named does not.
    let only_notifications = manifest(
        json!([{"id": "notifications.publish.v1", "scope": "installation"}]),
        json!([]),
    );
    assert_eq!(
        carry(&approved, &requested(&only_notifications).unwrap(), &[], ID)
            .unwrap()
            .len(),
        3
    );
    // Root's secret reads stay unchanged. Another installation's grants never carry.
    let mut with_secret = approved.clone();
    with_secret.push(grant("app.secret.read", "secretReferences", "token"));
    assert!(
        carry(&with_secret, &requested_now, &keys(), ID)
            .unwrap()
            .contains(&with_secret[with_secret.len() - 1])
    );
    assert_eq!(carry(&approved, &requested_now, &keys(), "app-other"), None);
    // An installation approved before approvals were recorded carries an empty set.
    assert_eq!(carry(&[], &[], &[], ID), Some(Vec::new()));
    assert_eq!(carry(&[], &requested_now, &keys(), ID), None);
}

#[test]
fn staging_approves_exactly_or_carries_and_refuses_otherwise() {
    let full = full_approval();
    let explicit = approve(&monitoring(), Some(&full), &[], None, ID).unwrap();
    assert_eq!(explicit.grants.len(), 6);
    assert_eq!(explicit.explicit, Some(requested(&monitoring()).unwrap()));
    let approved = explicit.grants;
    assert_eq!(
        approve(&monitoring(), None, &approved, None, ID).unwrap(),
        Decision {
            grants: approved.clone(),
            explicit: None,
        }
    );
    assert_eq!(
        approve(&monitoring(), None, &[], None, ID),
        Err(ApprovalRequired)
    );
    assert_eq!(
        approve(&monitoring(), Some(&full[1..]), &approved, None, ID),
        Err(ApprovalRequired)
    );
    assert_eq!(
        approve(&manifest(json!([]), json!([])), None, &[], None, ID),
        Ok(Decision {
            grants: Vec::new(),
            explicit: None,
        })
    );
    let error = io::Error::from(ApprovalRequired);
    assert!(approval_required(&error));
    assert!(!approval_required(&io::Error::other("other")));
}

#[test]
fn root_secret_reads_survive_an_explicit_approval() {
    let mut keyed = grant("app.secret.read", "secretReferences", "token");
    keyed.permission_key = Some("manage".into());
    let mut dropped_key = grant("app.secret.read", "secretReferences", "legacy");
    dropped_key.permission_key = Some("retired".into());
    let carried = vec![
        grant("app.secret.read", "secretReferences", "other"),
        keyed.clone(),
        dropped_key,
        grant("proxy.hosts.read.v1", "proxyHosts", OTHER_HOST),
    ];
    let decided = approve(&monitoring(), Some(&full_approval()), &carried, None, ID).unwrap();
    // Secret reads with a declared permission key are kept, the old host is not.
    assert_eq!(decided.grants.len(), 8);
    assert!(decided.grants.contains(&keyed));
    assert!(decided.grants.contains(&carried[0]));
    assert!(!decided.grants.contains(&carried[2]));
    assert!(!decided.grants.contains(&carried[3]));
    let mut sorted = decided.grants.clone();
    sorted.sort();
    assert_eq!(decided.grants, sorted);
    assert!(within(&monitoring(), &decided.grants, ID));
    // Carrying keeps them as well, so both paths agree.
    assert!(
        approve(&monitoring(), None, &decided.grants, None, ID)
            .unwrap()
            .grants
            .contains(&keyed)
    );
    // The secret reads still count toward the limit of one approval.
    let many: Vec<_> = (0..MAX_GRANTS)
        .map(|index| grant("app.secret.read", "secretReferences", &format!("s{index}")))
        .collect();
    assert_eq!(
        approve(&monitoring(), Some(&full_approval()), &many, None, ID),
        Err(ApprovalRequired)
    );
}

#[test]
fn a_carry_never_widens_the_stored_approval_of_its_target() {
    let requested = requested(&monitoring()).unwrap();
    let mut approval = full_approval();
    approval.push(approved(
        "proxy.hosts.read.v1",
        "proxyHosts",
        Some(OTHER_HOST),
    ));
    // The running release reads two hosts as a service.
    let running = decide(&requested, &keys(), &approval, ID).unwrap();
    // The Owner approved the target for one host, without service access and with a key.
    let mut narrower = full_approval();
    narrower[0].allow_service = false;
    narrower[0].permission_key = Some("view".into());
    let stored = decide(&requested, &keys(), &narrower, ID).unwrap();
    let carried = carry_to(&running, Some(&stored), &requested, &keys(), ID).unwrap();
    assert_eq!(carried.len(), 6);
    let host = carried
        .iter()
        .find(|grant| grant.capability.id == "proxy.hosts.read.v1")
        .unwrap();
    assert_eq!(host.resource_id, HOST);
    assert!(!host.allow_service);
    assert_eq!(host.permission_key.as_deref(), Some("view"));
    // A stored approval never widens what is carried.
    let carried_back = carry_to(&stored, Some(&running), &requested, &keys(), ID).unwrap();
    assert!(carried_back.iter().all(|grant| stored.contains(grant)));
    // A target whose stored approval lost every host after a revocation needs an approval.
    let revoked: Vec<_> = stored
        .iter()
        .filter(|grant| grant.capability.id != "proxy.hosts.read.v1")
        .cloned()
        .collect();
    assert_eq!(
        carry_to(&running, Some(&revoked), &requested, &keys(), ID),
        None
    );
    assert_eq!(
        approve(&monitoring(), None, &running, Some(&revoked), ID),
        Err(ApprovalRequired)
    );
    assert_eq!(
        approve(&monitoring(), None, &running, Some(&stored), ID)
            .unwrap()
            .grants,
        carried
    );
    // Without a stored approval, the carry is unchanged.
    assert_eq!(
        carry_to(&running, None, &requested, &keys(), ID),
        carry(&running, &requested, &keys(), ID)
    );
}

#[test]
fn an_explicit_decision_narrows_the_approvals_of_other_releases() {
    // Another release reads two hosts, registers two provider profiles and reads a secret.
    let mut other = vec![
        grant("app.audit.record", "installation", ID),
        grant("app.provider.register", "providerProfiles", "monitoring"),
        grant("app.provider.register", "providerProfiles", "oidc"),
        grant("app.secret.read", "secretReferences", "token"),
        grant("proxy.hosts.read.v1", "proxyHosts", HOST),
        grant("proxy.hosts.read.v1", "proxyHosts", OTHER_HOST),
    ];
    // The Owner now approves one host without service access and with a permission key.
    let mut approval = full_approval();
    approval[0].allow_service = false;
    approval[0].permission_key = Some("view".into());
    let requested = requested(&monitoring()).unwrap();
    let decided = decide(&requested, &keys(), &approval, ID).unwrap();
    apply_decision(&mut other, &requested, &decided, ID);
    let mut narrowed_host = grant("proxy.hosts.read.v1", "proxyHosts", HOST);
    narrowed_host.allow_service = false;
    narrowed_host.permission_key = Some("view".into());
    assert_eq!(
        other,
        [
            grant("app.audit.record", "installation", ID),
            grant("app.provider.register", "providerProfiles", "monitoring"),
            // The decided release does not request this profile or secret reads.
            grant("app.provider.register", "providerProfiles", "oidc"),
            grant("app.secret.read", "secretReferences", "token"),
            narrowed_host,
        ]
    );
}

#[test]
fn root_and_every_launch_stay_within_the_request() {
    let manifest = monitoring();
    let granted = decide(
        &requested(&manifest).unwrap(),
        &keys(),
        &full_approval(),
        ID,
    )
    .unwrap();
    assert!(within(&manifest, &granted, ID));
    // Root may approve a subset, and secret reads that no release requests.
    assert!(within(&manifest, &[], ID));
    assert!(within(&manifest, &granted[..2], ID));
    let secret = grant("app.secret.read", "secretReferences", "token");
    assert!(within(&manifest, std::slice::from_ref(&secret), ID));
    let refused = [
        grant("diagnostics.upstream.probe.v1", "proxyHosts", HOST),
        grant("proxy.hosts.read.v1", "proxyHosts", "not-a-host"),
        grant("app.provider.register", "providerProfiles", "oidc"),
        grant("app.audit.record", "installation", "app-other"),
        grant("app.secret.read", "secretReferences", "Token"),
        Grant {
            permission_key: Some("admin".into()),
            ..granted[0].clone()
        },
    ];
    for grant in refused {
        assert!(
            !within(&manifest, std::slice::from_ref(&grant), ID),
            "{grant:?}"
        );
    }
    assert!(!within(&manifest, &[secret.clone(), secret], ID));
    // A declared capability without an approval flow is not grantable either.
    let docker = json!({
        "capabilities": [{"id": "docker.inventory.observe.v1", "scope": "dockerConnections"}],
        "providers": [],
        "permissions": [],
    });
    assert!(within(&docker, &[], ID));
    assert!(!within(
        &docker,
        &[grant(
            "docker.inventory.observe.v1",
            "dockerConnections",
            "local"
        )],
        ID
    ));
    assert!(within(
        &docker,
        &[grant("app.audit.record", "installation", ID)],
        ID
    ));
    let many = vec![grant("app.audit.record", "installation", ID); MAX_GRANTS + 1];
    assert!(!within(&manifest, &many, ID));
}

#[test]
fn proxy_hosts_are_named_by_lowercase_platform_ids() {
    for valid in [
        HOST,
        OTHER_HOST,
        "00000000-0000-0000-0000-000000000000",
        "ffffffff-ffff-ffff-ffff-ffffffffffff",
    ] {
        assert!(platform_host_id(valid), "{valid}");
    }
    for invalid in [
        "",
        "0b6f3c0e8d1a4f439c2e1d7a5b9e4f21",
        "0B6F3C0E-8D1A-4F43-9C2E-1D7A5B9E4F21",
        "0b6f3c0e-8d1a-0f43-9c2e-1d7a5b9e4f21",
        "0b6f3c0e-8d1a-4f43-7c2e-1d7a5b9e4f21",
        "0b6f3c0e-8d1a-4f43-9c2e-1d7a5b9e4f2",
        "0b6f3c0e-8d1a-4f43-9c2e-1d7a5b9e4f21a",
        "0b6f3c0e_8d1a-4f43-9c2e-1d7a5b9e4f21",
        "0b6f3c0g-8d1a-4f43-9c2e-1d7a5b9e4f21",
    ] {
        assert!(!platform_host_id(invalid), "{invalid}");
    }
}
