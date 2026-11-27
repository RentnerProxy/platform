use super::*;
use crate::app_manager::{catalog, journal::Release};
use serde_json::{Value, json};

const APP: &str = "rentnerproxy.greeting";
const ID: &str = "greeting-test";

fn release(version: &str, digest: char) -> Release {
    Release {
        version: version.into(),
        archive_sha256: digest.to_string().repeat(64),
        manifest_sha256: "f".repeat(64),
        catalog_revision: 2,
    }
}

fn committed() -> Slot {
    Slot {
        uid: 20_003,
        app_id: APP.into(),
        generation: 7,
        active: Some(release("1.9.2", 'a')),
        previous: Some(release("1.8.7", 'b')),
        desired_running: true,
        ..Default::default()
    }
}

fn request(action: &str, target: Option<&Release>) -> Request {
    let mut value = json!({
        "action": action,
        "installationId": ID,
        "expected": {"version": "1.9.2", "archiveSha256": "a".repeat(64), "generation": 7},
    });
    if let Some(target) = target {
        value["target"] = json!(ReleaseSelection::from(target));
    }
    let request: Request = serde_json::from_value(value).unwrap();
    assert!(request.valid());
    request
}

fn entry(release: &Release, availability: &str) -> CatalogEntry {
    serde_json::from_value(json!({
        "appId": APP,
        "version": release.version,
        "archiveSha256": release.archive_sha256,
        "name": "Greeting",
        "summary": "Say hello",
        "publisher": "RentnerProxy",
        "hasUi": true,
        "availability": availability,
    }))
    .unwrap()
}

#[test]
fn only_the_latest_newer_eligible_release_is_offered_with_its_exact_digest() {
    let mut row = Installation::new(ID, &committed(), true).unwrap();
    let new = release("1.10.0", 'c');
    row.set_update(&[
        entry(&release("1.9.1", 'd'), "available"),
        entry(&release("1.9.2", 'd'), "available"),
        entry(&release("1.10.0-rc.20", 'd'), "available"),
        entry(&new, "available"),
        entry(&release("2.0.0", 'e'), "grantsRequired"),
        entry(&release("3.0.0", 'e'), "incompatible"),
    ]);
    assert_eq!(row.update, Some((&new).into()));
    assert!(row.offers(&request("update", Some(&new)), &[]));
    for reject in [
        release("1.10.0", 'd'),
        release("1.9.2", 'a'),
        release("1.8.7", 'b'),
    ] {
        assert!(!row.offers(&request("update", Some(&reject)), &[]));
    }
    assert!(strictly_newer("1.10.0-rc.10", "1.10.0-rc.9"));
    assert!(!strictly_newer("1.10.0-rc.10", "1.10.0"));
    assert!(!strictly_newer("1.10.0+other", "1.10.0"));
}

const HOST: &str = "0b6f3c0e-8d1a-4f43-9c2e-1d7a5b9e4f21";

fn read_hosts() -> Value {
    json!({"id": "proxy.hosts.read.v1", "scope": "proxyHosts"})
}

fn support(id: &str) -> Value {
    json!({"capability": {"id": id, "scope": "installation"}, "allowService": true})
}

/// A listed release that requests reading proxy hosts and, when `notify`, publishing
/// notifications.
fn requesting(release: &Release, notify: bool) -> CatalogEntry {
    let mut value = serde_json::to_value(entry(release, "available")).unwrap();
    let mut grants = vec![
        json!({"capability": read_hosts(), "allowService": true}),
        support("app.events.subscribe"),
        support("app.audit.record"),
    ];
    if notify {
        grants.push(json!({
            "capability": {"id": "notifications.publish.v1", "scope": "installation"},
            "allowService": true,
        }));
    }
    value["grants"] = grants.into();
    value["permissionKeys"] = json!(["view"]);
    serde_json::from_value(value).unwrap()
}

fn granted(id: &str, scope: &str, resource_id: &str) -> Grant {
    serde_json::from_value(json!({
        "capability": {"id": id, "scope": scope},
        "resourceId": resource_id,
        "allowService": true,
    }))
    .unwrap()
}

/// The running release, approved to read one proxy host.
fn approved() -> Slot {
    let mut slot = committed();
    let active = slot.active.clone().unwrap();
    slot.approve(
        &active,
        vec![
            granted("app.audit.record", "installation", ID),
            granted("app.events.subscribe", "installation", ID),
            granted("proxy.hosts.read.v1", "proxyHosts", HOST),
        ],
    );
    slot
}

fn with(mut request: Value, field: &str, value: Value) -> Request {
    request[field] = value;
    serde_json::from_value(request).unwrap()
}

#[test]
fn updates_that_request_new_grants_need_an_approval_that_receipts_never_repeat() {
    let target = release("1.10.0", 'c');
    // An installation approved before approvals were recorded carries nothing.
    let mut legacy = Installation::new(ID, &committed(), true).unwrap();
    assert_eq!(
        serde_json::to_value(&legacy).unwrap()["grants"],
        Value::Null
    );
    legacy.set_update(&[requesting(&target, false)]);
    assert_eq!(legacy.update, Some((&target).into()));
    assert!(legacy.update_requires_approval);
    let update = request("update", Some(&target));
    let listing = [requesting(&target, false)];
    assert!(legacy.offers(&update, &listing));
    assert!(!legacy.approves(&update, &listing));
    let approval = json!([
        {"capability": read_hosts(), "resourceId": HOST, "allowService": true, "permissionKey": "view"},
        support("app.events.subscribe"),
        support("app.audit.record"),
    ]);
    let approved_update = with(serde_json::to_value(&update).unwrap(), "approval", approval);
    assert!(approved_update.valid());
    assert!(legacy.approves(&approved_update, &listing));
    let receipt = serde_json::to_value(&approved_update).unwrap();
    assert!(receipt.get("approval").is_none(), "{receipt}");
    assert_ne!(approved_update, update);

    // The approved installation carries its grants to a release that requests nothing new.
    let mut row = Installation::new(ID, &approved(), true).unwrap();
    let serialized = serde_json::to_value(&row).unwrap();
    assert_eq!(serialized["grants"].as_array().unwrap().len(), 3);
    assert_eq!(serialized["updateRequiresApproval"], false);
    row.set_update(&listing);
    assert!(!row.update_requires_approval);
    assert!(row.approves(&update, &listing));
    // A release that also publishes notifications needs a new approval.
    let wider = [requesting(&target, true)];
    row.set_update(&wider);
    assert!(row.update_requires_approval);
    assert_eq!(
        serde_json::to_value(&row).unwrap()["updateRequiresApproval"],
        true
    );
    assert!(!row.approves(&update, &wider));
    // An approval that differs from the target's request is refused as well.
    assert!(!row.approves(&approved_update, &wider));
    // A removed installation offers its retained approval to a reinstall.
    let mut removed = approved();
    removed.removed_release = removed.active.take().as_ref().map(Into::into);
    removed.removal = Removal::Removed;
    let removed = Installation::new(ID, &removed, false).unwrap();
    assert_eq!(
        serde_json::to_value(&removed).unwrap()["grants"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    let reinstall = request("reinstall", Some(&target));
    assert!(removed.approves(&reinstall, &listing));
    assert!(!removed.approves(&reinstall, &wider));
    // Only updates and reinstalls take an approval.
    let deactivate = request("deactivate", None);
    assert!(
        !with(
            serde_json::to_value(&deactivate).unwrap(),
            "approval",
            json!([])
        )
        .valid()
    );
}

#[test]
fn update_offers_stay_within_the_stored_approval_of_their_target() {
    let target = release("1.10.0", 'c');
    let listing = [requesting(&target, false)];
    let update = request("update", Some(&target));
    let support = || {
        vec![
            granted("app.audit.record", "installation", ID),
            granted("app.events.subscribe", "installation", ID),
        ]
    };
    // The installation approved the target before for the host the running release reads.
    let mut slot = approved();
    let mut stored = support();
    stored.push(granted("proxy.hosts.read.v1", "proxyHosts", HOST));
    slot.approve(&target, stored);
    let mut row = Installation::new(ID, &slot, true).unwrap();
    row.set_update(&listing);
    assert!(!row.update_requires_approval);
    assert!(row.approves(&update, &listing));
    // A revocation left the target's stored approval without any host, so carrying the running
    // release's host would widen it again. The update needs an approval, as staging decides.
    slot.approve(&target, support());
    let mut row = Installation::new(ID, &slot, true).unwrap();
    assert!(
        serde_json::to_value(&row)
            .unwrap()
            .get("approvals")
            .is_none()
    );
    row.set_update(&listing);
    assert!(row.update_requires_approval);
    assert!(!row.approves(&update, &listing));
}

#[test]
fn a_revocation_that_cannot_reach_the_app_reports_every_failed_fence_step() {
    let published = || {
        io::Error::new(
            io::ErrorKind::WouldBlock,
            "Generation grants rejected (503)",
        )
    };
    // A complete fence stopped the app, which the receipt reports as such.
    let failed = fail_closed(published(), Ok(()), Ok(()));
    assert!(revoked_and_stopped(&failed));
    assert_eq!(failed.kind(), io::ErrorKind::WouldBlock);
    assert_eq!(
        failed.to_string(),
        "Revocation stopped the app that could not apply it: Generation grants rejected (503)"
    );
    for (recorded, fenced) in [
        (
            Err(io::Error::other("Manager journal capacity exceeded")),
            Ok(()),
        ),
        (
            Ok(()),
            Err(io::Error::other("Generation retire rejected (503)")),
        ),
    ] {
        assert!(!revoked_and_stopped(&fail_closed(
            published(),
            recorded,
            fenced
        )));
    }
    let failed = fail_closed(
        published(),
        Err(io::Error::other("Manager journal capacity exceeded")),
        Err(io::Error::other("Generation retire rejected (503)")),
    );
    // Without a complete fence, the receipt still reports the unavailable authority.
    assert!(!revoked_and_stopped(&failed));
    assert_eq!(failed.kind(), io::ErrorKind::WouldBlock);
    assert_eq!(
        failed.to_string(),
        "Generation grants rejected (503); recovery state: Manager journal capacity exceeded; \
         fence: Generation retire rejected (503)"
    );
}

#[test]
fn revocations_name_approved_grants_of_an_installed_release() {
    let revoke = |grants: Value| {
        let base = serde_json::to_value(request("deactivate", None)).unwrap();
        let mut value = base.clone();
        value["action"] = "revoke".into();
        with(value, "grants", grants)
    };
    let host = json!({"capability": read_hosts(), "resourceId": HOST});
    let audit = json!({"capability": {"id": "app.audit.record", "scope": "installation"}, "resourceId": ID});
    let request = revoke(json!([host, audit]));
    assert!(request.valid());
    let receipt = serde_json::to_value(&request).unwrap();
    assert_eq!(receipt["action"], "revoke");
    assert!(receipt.get("grants").is_none(), "{receipt}");
    for invalid in [
        revoke(json!([])),
        revoke(json!([host, host])),
        revoke(serde_json::Value::Array(
            (0..=MAX_GRANTS)
                .map(|index| json!({"capability": read_hosts(), "resourceId": format!("h{index}")}))
                .collect(),
        )),
    ] {
        assert!(!invalid.valid());
    }
    let mut targeted = serde_json::to_value(&request).unwrap();
    targeted["grants"] = json!([host]);
    targeted["target"] = json!(ReleaseSelection::from(&release("1.10.0", 'c')));
    assert!(!serde_json::from_value::<Request>(targeted).unwrap().valid());
    let missing: Value = serde_json::to_value(revoke(json!([host]))).unwrap();
    assert!(!serde_json::from_value::<Request>(missing).unwrap().valid());

    let mut slot = approved();
    let running = Installation::new(ID, &slot, true).unwrap();
    assert!(running.permits(&request));
    assert!(!running.permits(&revoke(
        json!([{"capability": read_hosts(), "resourceId": "5c1e2f3a-4b5d-4e6f-8a7b-9c0d1e2f3a4b"}])
    )));
    let mut stale = serde_json::to_value(&request).unwrap();
    stale["grants"] = json!([host]);
    stale["expected"]["generation"] = 6.into();
    assert!(!running.permits(&serde_json::from_value(stale).unwrap()));
    assert!(
        !Installation::new(ID, &committed(), true)
            .unwrap()
            .permits(&request)
    );
    slot.desired_running = false;
    assert!(
        Installation::new(ID, &slot, false)
            .unwrap()
            .permits(&request)
    );
    slot.pending_fence = true;
    assert!(
        Installation::new(ID, &slot, false)
            .unwrap()
            .permits(&request)
    );
    slot.removed_release = slot.active.take().as_ref().map(Into::into);
    slot.removal = Removal::Removed;
    assert!(
        !Installation::new(ID, &slot, false)
            .unwrap()
            .permits(&request)
    );
}

#[test]
fn installations_report_the_providers_of_their_exact_listed_release() {
    let listed = |release: &Release, providers: Value| {
        let mut value = serde_json::to_value(entry(release, "available")).unwrap();
        value["providers"] = providers;
        serde_json::from_value::<CatalogEntry>(value).unwrap()
    };
    let mut row = Installation::new(ID, &committed(), true).unwrap();
    assert_eq!(
        serde_json::to_value(&row).unwrap()["providers"],
        Value::Null
    );
    row.set_providers(&[
        listed(&release("1.9.2", 'd'), json!(["dns"])),
        listed(&release("1.10.0", 'a'), json!(["oidc"])),
    ]);
    assert_eq!(row.providers, None);
    row.set_providers(&[
        listed(&release("1.9.2", 'd'), json!(["dns"])),
        listed(&release("1.9.2", 'a'), json!(["monitoring", "crowdsec"])),
    ]);
    assert_eq!(
        serde_json::to_value(&row).unwrap()["providers"],
        json!(["monitoring", "crowdsec"])
    );
    row.set_providers(&[]);
    assert_eq!(row.providers, None);
}

#[test]
fn target_checks_cover_only_installations_the_platform_may_start_again() {
    use crate::app_install::TargetSupport;

    let mut disabled = committed();
    disabled.desired_running = false;
    let mut removed = committed();
    removed.removal = Removal::Removed;
    removed.removed_release = Some(ReleaseSelection::from(&release("1.8.7", 'b')));
    let rows = [
        Installation::new("running-app", &committed(), true).unwrap(),
        Installation::new("removed-app", &removed, false).unwrap(),
        Installation::new("disabled-app", &disabled, false).unwrap(),
    ];
    let checked = check_target(&rows, |releases| {
        let seen: Vec<_> = releases
            .iter()
            .map(|release| (release.app_id, release.version, release.archive_sha256))
            .collect();
        let digest = "a".repeat(64);
        assert_eq!(
            seen,
            [
                (APP, "1.9.2", digest.as_str()),
                (APP, "1.9.2", digest.as_str())
            ]
        );
        Ok(vec![
            TargetCheck {
                providers: Some(vec!["monitoring".into()]),
                support: TargetSupport::Incompatible,
            },
            TargetCheck {
                providers: None,
                support: TargetSupport::Unknown,
            },
        ])
    })
    .unwrap();
    assert_eq!(
        serde_json::to_value(&checked).unwrap(),
        json!([
            {
                "installationId": "running-app", "appId": APP, "version": "1.9.2",
                "archiveSha256": "a".repeat(64), "state": "running",
                "providers": ["monitoring"], "target": "incompatible",
            },
            {
                "installationId": "disabled-app", "appId": APP, "version": "1.9.2",
                "archiveSha256": "a".repeat(64), "state": "disabled",
                "providers": null, "target": "unknown",
            },
        ])
    );
    let incomplete = check_target(&rows, |_| Ok(Vec::new())).err().unwrap();
    assert_eq!(incomplete.to_string(), "Target check result is incomplete");
    let failed = check_target(&rows, |_| Err(io::Error::other("catalog unavailable")))
        .err()
        .unwrap();
    assert_eq!(failed.to_string(), "catalog unavailable");
}

#[test]
fn lifecycle_admission_checks_generation_release_state_and_rollback_identity() {
    let mut slot = committed();
    let running = Installation::new(ID, &slot, true).unwrap();
    let mut deactivate = request("deactivate", None);
    assert!(running.permits(&deactivate));
    deactivate.expected.generation -= 1;
    assert!(!running.permits(&deactivate));
    deactivate.expected.generation += 1;
    deactivate.expected.archive_sha256 = "f".repeat(64);
    assert!(!running.permits(&deactivate));
    assert!(!running.permits(&request("reactivate", None)));
    assert!(!running.permits(&request("purge", None)));
    assert!(running.permits(&request("rollback", slot.previous.as_ref())));
    assert!(!running.permits(&request("rollback", Some(&release("1.8.7", 'c')))));

    slot.desired_running = false;
    let disabled = Installation::new(ID, &slot, false).unwrap();
    assert!(disabled.permits(&request("reactivate", None)));
    assert!(disabled.permits(&request("deactivate", None)));
    assert!(!disabled.permits(&request("recover", None)));
    assert!(!disabled.permits(&request("update", Some(&release("1.10.0", 'c')))));

    slot.pending_fence = true;
    let interrupted = Installation::new(ID, &slot, false).unwrap();
    assert!(interrupted.permits(&request("recover", None)));
    assert!(interrupted.permits(&request("deactivate", None)));
    assert!(!interrupted.permits(&request("reactivate", None)));

    slot.removal = Removal::Removing;
    assert!(
        Installation::new(ID, &slot, false)
            .unwrap()
            .permits(&request("uninstall", None))
    );
    slot.removed_release = slot.active.take().as_ref().map(Into::into);
    slot.removal = Removal::Removed;
    let removed = Installation::new(ID, &slot, false).unwrap();
    assert!(removed.permits(&request("purge", None)));
    assert!(!removed.permits(&request("uninstall", None)));
    let reinstall = release("1.10.0", 'c');
    let reinstall_request = request("reinstall", Some(&reinstall));
    assert!(removed.offers(&reinstall_request, &[entry(&reinstall, "available")]));
    assert!(!removed.offers(&reinstall_request, &[]));
    assert!(!removed.offers(&reinstall_request, &[entry(&reinstall, "grantsRequired")]));
    slot.removal = Removal::Purging;
    assert!(
        Installation::new(ID, &slot, false)
            .unwrap()
            .permits(&request("purge", None))
    );
    slot.removal = Removal::Purged;
    assert!(Installation::new(ID, &slot, false).is_none());
}

#[test]
fn offline_management_coalesces_retries_and_serializes_with_catalog_install() {
    let (endpoint, mut queue, selection) = catalog::tests::ready_endpoint();
    endpoint
        .publish(vec![Installation::new(ID, &committed(), true).unwrap()])
        .unwrap();
    let deactivate = request("deactivate", None);
    let pending = endpoint.submit_lifecycle(deactivate.clone()).unwrap();
    assert_eq!(serde_json::to_value(pending).unwrap()["status"], "pending");
    assert!(endpoint.submit_lifecycle(deactivate.clone()).is_ok());
    assert!(matches!(
        endpoint.submit(selection.clone()),
        Err(catalog::Failure::Conflict)
    ));
    assert!(matches!(
        endpoint.submit_lifecycle(request("uninstall", None)),
        Err(catalog::Failure::Conflict)
    ));
    assert_eq!(
        queue.try_recv().unwrap(),
        catalog::Request::Lifecycle(deactivate.clone())
    );
    assert!(queue.try_recv().is_err());
    endpoint
        .finish_lifecycle(deactivate, Err(io::Error::other(IncompatibleData)))
        .unwrap();
    let view: Value = serde_json::from_slice(&endpoint.view().unwrap()).unwrap();
    assert_eq!(view["lifecycle"]["status"], "failed");
    assert_eq!(view["lifecycle"]["error"], "incompatibleData");
    assert_eq!(view["installations"][0]["state"], "running");

    assert!(endpoint.submit(selection).is_ok());
    assert!(matches!(
        endpoint.submit_lifecycle(request("deactivate", None)),
        Err(catalog::Failure::Conflict)
    ));

    let (offline, _offline_queue) = catalog::Endpoint::new(None);
    let mut slot = committed();
    slot.desired_running = false;
    offline
        .publish(vec![Installation::new(ID, &slot, false).unwrap()])
        .unwrap();
    assert!(
        offline
            .submit_lifecycle(request("reactivate", None))
            .is_ok()
    );
    let view: Value = serde_json::from_slice(&offline.view().unwrap()).unwrap();
    assert_eq!(view["state"], "loading");
    assert_eq!(view["installations"][0]["state"], "disabled");
    assert_eq!(view["lifecycle"]["expected"]["generation"], 7);
}

#[test]
fn an_exact_replay_of_the_running_release_reaches_the_manager() {
    let active = release("1.9.2", 'a');
    let mut listed = serde_json::to_value(entry(&active, "available")).unwrap();
    listed["grants"] = json!([
        {"capability": {"id": "app.provider.register", "scope": "providerProfiles"},
         "resourceId": "monitoring", "allowService": true},
        {"capability": {"id": "app.events.subscribe", "scope": "installation"}, "allowService": true},
    ]);
    let (endpoint, mut queue) =
        catalog::tests::listing(vec![serde_json::from_value(listed).unwrap()]);
    let selection = |approval: Value| -> catalog::Selection {
        serde_json::from_value(json!({
            "appId": APP, "version": "1.9.2", "archiveSha256": "a".repeat(64),
            "approval": approval,
        }))
        .unwrap()
    };
    let events = json!({"capability": {"id": "app.events.subscribe", "scope": "installation"},
                        "allowService": true});
    let provider = json!({"capability": {"id": "app.provider.register", "scope": "providerProfiles"},
                          "resourceId": "monitoring", "allowService": true});
    // Root approved only the events for the running release.
    let mut slot = committed();
    slot.approve(
        &active,
        vec![
            serde_json::from_value(json!({
                "capability": {"id": "app.events.subscribe", "scope": "installation"},
                "resourceId": ID, "allowService": true,
            }))
            .unwrap(),
        ],
    );
    let replay = selection(json!([events]));
    // Unless the installation runs, the subset is no replay and needs a full approval.
    endpoint
        .publish(vec![Installation::new(ID, &slot, false).unwrap()])
        .unwrap();
    assert!(matches!(
        endpoint.submit(replay.clone()),
        Err(catalog::Failure::ApprovalRequired)
    ));
    endpoint
        .publish(vec![Installation::new(ID, &slot, true).unwrap()])
        .unwrap();
    // Another subset still needs a full approval. The exact one reaches the manager, which
    // compares it with the journal again.
    assert!(matches!(
        endpoint.submit(selection(json!([provider]))),
        Err(catalog::Failure::ApprovalRequired)
    ));
    assert!(queue.try_recv().is_err());
    assert!(endpoint.submit(replay.clone()).is_ok());
    assert_eq!(queue.try_recv().unwrap(), catalog::Request::Install(replay));
}

#[test]
fn dependency_refusals_are_reported_apart_from_conflicts() {
    let (endpoint, mut queue, _) = catalog::tests::ready_endpoint();
    endpoint
        .publish(vec![Installation::new(ID, &committed(), true).unwrap()])
        .unwrap();
    for (kind, reported) in [
        (io::ErrorKind::ResourceBusy, "dependencyBlocked"),
        (io::ErrorKind::AlreadyExists, "conflict"),
    ] {
        let uninstall = request("uninstall", None);
        endpoint.submit_lifecycle(uninstall.clone()).unwrap();
        assert_eq!(
            queue.try_recv().unwrap(),
            catalog::Request::Lifecycle(uninstall.clone())
        );
        endpoint
            .finish_lifecycle(uninstall, Err(io::Error::new(kind, "fixture refusal")))
            .unwrap();
        let view: Value = serde_json::from_slice(&endpoint.view().unwrap()).unwrap();
        assert_eq!(view["lifecycle"]["status"], "failed");
        assert_eq!(view["lifecycle"]["error"], reported);
        assert_eq!(view["installations"][0]["state"], "running");
    }
}

#[test]
fn source_outages_are_reported_by_the_source_that_did_not_answer() {
    use crate::app_install::{Source, SourceUnavailable};

    let (endpoint, mut queue, _) = catalog::tests::ready_endpoint();
    endpoint
        .publish(vec![Installation::new(ID, &committed(), true).unwrap()])
        .unwrap();
    for (source, reported) in [
        (Source::Catalog, "catalogUnavailable"),
        (Source::Package, "packageSourceUnavailable"),
        (Source::Network, "networkUnavailable"),
    ] {
        let deactivate = request("deactivate", None);
        endpoint.submit_lifecycle(deactivate.clone()).unwrap();
        assert_eq!(
            queue.try_recv().unwrap(),
            catalog::Request::Lifecycle(deactivate.clone())
        );
        let outage = SourceUnavailable::error(source, "fixture outage");
        endpoint.finish_lifecycle(deactivate, Err(outage)).unwrap();
        let view: Value = serde_json::from_slice(&endpoint.view().unwrap()).unwrap();
        assert_eq!(view["lifecycle"]["status"], "failed");
        assert_eq!(view["lifecycle"]["error"], reported);
        assert_eq!(view["installations"][0]["state"], "running");
    }
}

#[test]
fn installations_carry_the_display_name_of_their_verified_manifest() {
    let named = |release: &Release, name: &str| {
        let mut value = serde_json::to_value(entry(release, "available")).unwrap();
        value["name"] = name.into();
        serde_json::from_value::<CatalogEntry>(value).unwrap()
    };
    let listing = [
        named(&release("1.9.2", 'd'), "Other digest"),
        named(&release("1.9.2", 'a'), "Listed Greeting"),
    ];
    let row = Installation::new(ID, &committed(), true).unwrap();
    assert_eq!(serde_json::to_value(&row).unwrap()["name"], Value::Null);
    let mut listed = row.clone();
    listed.set_listed_name(&listing);
    assert_eq!(
        serde_json::to_value(&listed).unwrap()["name"],
        "Listed Greeting"
    );
    let mut unlisted = row.clone();
    unlisted.set_listed_name(&listing[..1]);
    assert_eq!(
        serde_json::to_value(&unlisted).unwrap()["name"],
        Value::Null
    );
    // The manifest the running generation loaded wins over the listing.
    let mut loaded = row.with_name(Some("Loaded Greeting".into()));
    loaded.set_listed_name(&listing);
    assert_eq!(
        serde_json::to_value(&loaded).unwrap()["name"],
        "Loaded Greeting"
    );
}
