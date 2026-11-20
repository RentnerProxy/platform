use super::*;

#[test]
fn generation_path_identity_and_payload_are_unambiguous() {
    assert_eq!(generation_number("1"), Some(1));
    assert_eq!(generation_number("9007199254740991"), Some(MAX_GENERATION));
    for number in ["", "0", "01", "+1", "1.0", "9007199254740992", "%31"] {
        assert_eq!(generation_number(number), None);
    }
    assert!(json_object(br#"{"field":["value"]}"#).is_some());
    assert!(json_object(br#"{"field":1,"field":2}"#).is_none());
    assert!(json_object(br#"["value"]"#).is_none());
    let one_hundred = vec![0; 100];
    let too_many = vec![0; 101];
    assert!(bounded_lists(&serde_json::json!({"list":one_hundred})));
    assert!(!bounded_lists(&serde_json::json!({"list":too_many})));
}

#[tokio::test]
async fn generation_replacement_and_drain_revoke_open_entries() {
    use crate::app_install::StagedPackage;
    use serde_json::json;

    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let temp = tempfile::tempdir_in("/run").unwrap();
    fs::create_dir(temp.path().join("ui")).unwrap();
    fs::write(temp.path().join("ui/index.html"), b"hello").unwrap();
    let staged = StagedPackage {
        directory: temp.path().to_path_buf(),
        manifest: json!({
            "id": "fixture.test", "display": {"name": "Fixture"},
            "ui": {"entrypoint": "ui/index.html", "slots": []},
            "permissions": [], "capabilities": [],
        }),
        archive_sha256: "0".repeat(64),
        manifest_sha256: "1".repeat(64),
        catalog_revision: 1,
    };
    let registry = Registry::default();
    let publish = |generation| {
        let package = Package::load(&staged, "demo".to_owned(), generation, 20_000)
            .unwrap()
            .unwrap();
        registry.publish(package).unwrap()
    };
    let first = publish(1);
    let open = registry.entry("demo", 1).unwrap();
    assert_eq!(open.package.asset("index.html").unwrap(), b"hello");
    let (selected, resource, value) = selection(&registry, "/v1/apps/demo/1/metadata").unwrap();
    assert!(Arc::ptr_eq(&open, &selected));
    assert_eq!((resource, value), ("metadata", None));
    let second = publish(2);
    assert_eq!(
        registry.entry("demo", 1).err(),
        Some(StatusCode::PRECONDITION_FAILED)
    );
    assert_eq!(
        protected(&open, async { Ok(()) }).await,
        Err(StatusCode::PRECONDITION_FAILED)
    );
    drop(first);
    assert!(registry.entry("demo", 2).is_ok());
    drop(second);
    assert_eq!(registry.entry("demo", 2).err(), Some(StatusCode::NOT_FOUND));
}
