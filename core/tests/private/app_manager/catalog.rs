use serde_json::json;

use super::*;

fn greeting() -> Selection {
    Selection {
        app_id: "rentnerproxy.greeting".into(),
        version: "1.0.0".into(),
        archive_sha256: "a".repeat(64),
        approval: None,
    }
}

fn entry(selection: &Selection, availability: &str) -> CatalogEntry {
    let mut value = serde_json::to_value(selection).unwrap();
    value["name"] = json!("Greeting");
    value["summary"] = json!("Say hello");
    value["publisher"] = json!("RentnerProxy");
    value["hasUi"] = json!(true);
    value["availability"] = json!(availability);
    serde_json::from_value(value).unwrap()
}

pub(in crate::app_manager) fn ready_endpoint() -> (Endpoint, mpsc::Receiver<Request>, Selection) {
    let (endpoint, requests) = Endpoint::new(None);
    let selection = greeting();
    endpoint
        .finish_refresh(Ok(vec![entry(&selection, "available")]))
        .unwrap();
    (endpoint, requests, selection)
}

#[test]
fn accepts_only_listed_packages_and_coalesces_identical_requests() {
    let (endpoint, mut requests) = Endpoint::new(None);
    let selection = greeting();
    assert!(matches!(
        endpoint.submit(selection.clone()),
        Err(Failure::Unavailable)
    ));

    endpoint
        .finish_refresh(Ok(vec![entry(&selection, "grantsRequired")]))
        .unwrap();
    assert!(matches!(
        endpoint.submit(selection.clone()),
        Err(Failure::Conflict)
    ));

    endpoint
        .finish_refresh(Ok(vec![entry(&selection, "available")]))
        .unwrap();
    let mismatched = Selection {
        archive_sha256: "b".repeat(64),
        ..selection.clone()
    };
    assert!(matches!(
        endpoint.submit(mismatched.clone()),
        Err(Failure::Conflict)
    ));
    let accepted = endpoint.submit(selection.clone()).unwrap();
    let repeated = endpoint.submit(selection.clone()).unwrap();
    assert_eq!(
        serde_json::to_value(&accepted).unwrap(),
        serde_json::to_value(&repeated).unwrap()
    );
    assert!(matches!(
        endpoint.submit(mismatched),
        Err(Failure::Conflict)
    ));
    assert_eq!(
        requests.try_recv().unwrap(),
        Request::Install(selection.clone())
    );
    assert!(matches!(
        requests.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));

    endpoint
        .finish(selection, Ok("greeting-test".into()))
        .unwrap();
    let view: serde_json::Value = serde_json::from_slice(&endpoint.view().unwrap()).unwrap();
    assert_eq!(view["state"], "ready");
    assert_eq!(view["install"]["status"], "installed");
    assert_eq!(view["install"]["installationId"], "greeting-test");
}

/// A listed release that requests events, an audit trail and one provider profile.
fn requesting(selection: &Selection) -> CatalogEntry {
    let mut value = serde_json::to_value(entry(selection, "available")).unwrap();
    value["grants"] = json!([
        {"capability": {"id": "app.provider.register", "scope": "providerProfiles"},
         "resourceId": "monitoring", "allowService": true},
        {"capability": {"id": "app.events.subscribe", "scope": "installation"}, "allowService": true},
    ]);
    value["permissionKeys"] = json!(["view"]);
    serde_json::from_value(value).unwrap()
}

fn approving(selection: &Selection, approval: serde_json::Value) -> Selection {
    let mut value = serde_json::to_value(selection).unwrap();
    value["approval"] = approval;
    serde_json::from_value(value).unwrap()
}

#[test]
fn installs_need_an_exact_approval_that_receipts_never_repeat() {
    let (endpoint, mut requests) = Endpoint::new(None);
    let plain = greeting();
    endpoint
        .finish_refresh(Ok(vec![requesting(&plain)]))
        .unwrap();
    let exact = json!([
        {"capability": {"id": "app.provider.register", "scope": "providerProfiles"},
         "resourceId": "monitoring", "allowService": false, "permissionKey": "view"},
        {"capability": {"id": "app.events.subscribe", "scope": "installation"}, "allowService": true},
    ]);
    let mut extra = exact.clone();
    extra.as_array_mut().unwrap().push(json!(
        {"capability": {"id": "app.audit.record", "scope": "installation"}, "allowService": true}
    ));
    let mut partial = exact.clone();
    partial.as_array_mut().unwrap().pop();
    // Without an approval, or with one that differs from the request, nothing is admitted.
    for refused in [
        plain.clone(),
        approving(&plain, extra),
        approving(&plain, partial),
    ] {
        assert!(matches!(
            endpoint.submit(refused),
            Err(Failure::ApprovalRequired)
        ));
    }
    assert!(requests.try_recv().is_err());

    let approved = approving(&plain, exact.clone());
    assert!(approved.valid());
    let accepted = endpoint.submit(approved.clone()).unwrap();
    let receipt = serde_json::to_value(&accepted).unwrap();
    assert_eq!(receipt["status"], "installing");
    assert!(receipt.get("approval").is_none(), "{receipt}");
    // The identical approval coalesces. Another approval for the same release is a conflict.
    assert!(endpoint.submit(approved.clone()).is_ok());
    let mut other = exact.clone();
    other[0]["allowService"] = json!(true);
    assert!(matches!(
        endpoint.submit(approving(&plain, other)),
        Err(Failure::Conflict)
    ));
    assert_eq!(
        requests.try_recv().unwrap(),
        Request::Install(approved.clone())
    );
    assert!(requests.try_recv().is_err());
    let view: serde_json::Value = serde_json::from_slice(&endpoint.view().unwrap()).unwrap();
    assert!(view["install"].get("approval").is_none(), "{view}");
    assert_eq!(view["entries"][0]["grants"][0]["resourceId"], "monitoring");
    assert!(view["entries"][0]["grants"][1].get("resourceId").is_none());
    assert_eq!(view["entries"][0]["permissionKeys"], json!(["view"]));

    // Staging decides again from fresh metadata and reports a refusal as such.
    endpoint
        .finish(
            approved,
            Err(io::Error::from(
                crate::app_install::grants::ApprovalRequired,
            )),
        )
        .unwrap();
    let view: serde_json::Value = serde_json::from_slice(&endpoint.view().unwrap()).unwrap();
    assert_eq!(view["install"]["status"], "failed");
    assert_eq!(view["install"]["error"], "approvalRequired");

    let oversized = approving(
        &plain,
        serde_json::Value::Array(vec![exact[1].clone(); MAX_GRANTS + 1]),
    );
    assert!(!oversized.valid());
}

#[test]
fn failed_refresh_keeps_the_last_verified_listing_and_allows_recovery() {
    let (endpoint, _) = Endpoint::new(None);
    let fail = || {
        endpoint
            .finish_refresh(Err(io::Error::other("fixture offline")))
            .unwrap()
    };
    let view = || serde_json::from_slice::<serde_json::Value>(&endpoint.view().unwrap()).unwrap();
    fail();
    assert_eq!(view()["state"], "unavailable");
    assert_eq!(view()["entries"], json!([]));

    endpoint
        .finish_refresh(Ok(vec![entry(&greeting(), "available")]))
        .unwrap();
    let listing = view()["entries"].clone();
    fail();
    assert_eq!(view()["state"], "stale");
    assert_eq!(view()["entries"], listing);

    endpoint.finish_refresh(Ok(vec![])).unwrap();
    assert_eq!(view()["state"], "ready");
    assert_eq!(view()["entries"], json!([]));
}

#[test]
fn a_failed_install_releases_the_queue_and_reports_a_safe_failure() {
    let (endpoint, mut requests, selection) = ready_endpoint();
    for (kind, failure) in [
        (io::ErrorKind::AlreadyExists, "conflict"),
        (io::ErrorKind::TimedOut, "unavailable"),
        (io::ErrorKind::InvalidData, "installFailed"),
    ] {
        endpoint.submit(selection.clone()).unwrap();
        assert_eq!(
            requests.try_recv().unwrap(),
            Request::Install(selection.clone())
        );
        endpoint
            .finish(
                selection.clone(),
                Err(io::Error::new(kind, "fixture failure")),
            )
            .unwrap();
        let view: serde_json::Value = serde_json::from_slice(&endpoint.view().unwrap()).unwrap();
        assert_eq!(view["install"]["status"], "failed");
        assert_eq!(view["install"]["error"], failure);
    }
    for (source, failure) in [
        (Source::Catalog, "catalogUnavailable"),
        (Source::Package, "packageSourceUnavailable"),
        (Source::Network, "networkUnavailable"),
    ] {
        endpoint.submit(selection.clone()).unwrap();
        assert_eq!(
            requests.try_recv().unwrap(),
            Request::Install(selection.clone())
        );
        let outage = crate::app_install::SourceUnavailable::error(source, "fixture outage");
        endpoint.finish(selection.clone(), Err(outage)).unwrap();
        let view: serde_json::Value = serde_json::from_slice(&endpoint.view().unwrap()).unwrap();
        assert_eq!(view["install"]["status"], "failed");
        assert_eq!(view["install"]["error"], failure);
    }
}
