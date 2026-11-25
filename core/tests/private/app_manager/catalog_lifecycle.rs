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
