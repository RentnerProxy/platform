use serde_json::json;

use super::*;

#[test]
fn accepts_only_listed_packages_and_coalesces_identical_requests() {
    let (endpoint, mut requests) = Endpoint::new(None);
    let selection = Selection {
        app_id: "rentnerproxy.greeting".into(),
        version: "1.0.0".into(),
        archive_sha256: "a".repeat(64),
    };
    assert!(matches!(
        endpoint.submit(selection.clone()),
        Err(Failure::Unavailable)
    ));

    let mut entry = serde_json::to_value(&selection).unwrap();
    entry["name"] = json!("Greeting");
    entry["summary"] = json!("Say hello");
    entry["publisher"] = json!("RentnerProxy");
    entry["availability"] = json!("grantsRequired");
    endpoint
        .finish_refresh(Ok(vec![serde_json::from_value(entry.clone()).unwrap()]))
        .unwrap();
    assert!(matches!(
        endpoint.submit(selection.clone()),
        Err(Failure::Conflict)
    ));

    entry["availability"] = json!("available");
    endpoint
        .finish_refresh(Ok(vec![serde_json::from_value(entry).unwrap()]))
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
    assert_eq!(requests.try_recv().unwrap(), selection);
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
