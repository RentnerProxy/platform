use serde_json::json;

use super::*;

fn greeting() -> Selection {
    Selection {
        app_id: "rentnerproxy.greeting".into(),
        version: "1.0.0".into(),
        archive_sha256: "a".repeat(64),
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
