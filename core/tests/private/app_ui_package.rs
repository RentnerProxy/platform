use super::*;
use serde_json::json;

#[test]
fn accepts_only_canonical_relative_package_paths() {
    for path in ["index.html", "nested/assets/app-v1.2.js", "Foo/Bar_3.svg"] {
        assert!(valid_relative_path(path), "{path}");
    }
    for path in [
        "",
        "/index.html",
        "a//b",
        "./index.html",
        "a/../b",
        "a/.",
        "trailing/",
        ".hidden",
        "a%2fb",
        "a%252fb",
        "a\\b",
        "https://app.test/index.html",
        "é.js",
    ] {
        assert!(!valid_relative_path(path), "{path}");
    }
}

#[test]
fn open_ui_files_are_bounded_and_do_not_follow_links() {
    use std::{fs, os::unix::fs::symlink};

    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let root = File::open(temp.path()).unwrap();
    fs::create_dir(temp.path().join("nested")).unwrap();
    fs::write(temp.path().join("nested/index.html"), b"hello").unwrap();
    assert_eq!(
        read_beneath(&root, "nested/index.html", 5).unwrap(),
        b"hello"
    );
    assert!(read_beneath(&root, "nested/index.html", 4).is_err());
    symlink("nested/index.html", temp.path().join("alias.html")).unwrap();
    symlink("nested", temp.path().join("folder-alias")).unwrap();
    assert!(read_beneath(&root, "alias.html", 5).is_err());
    assert!(read_beneath(&root, "folder-alias/index.html", 5).is_err());
    fs::hard_link(
        temp.path().join("nested/index.html"),
        temp.path().join("hard.html"),
    )
    .unwrap();
    assert!(read_beneath(&root, "hard.html", 5).is_err());
}

fn operation_document() -> Value {
    let operation = json!({
        "operationId": "greeting",
        "x-rentnerproxy-access": {
            "permissionKey": "read",
            "resource": {
                "capability": { "id": "proxy.hosts.read.v1", "scope": "proxyHosts" },
                "resourceIdField": "installationId",
            }
        },
        "requestBody": {
            "content": {
                "application/json": { "schema": {
                    "type": "object",
                    "properties": { "installationId": { "type": "string" } },
                    "required": ["installationId"],
                    "additionalProperties": false,
                } }
            }
        },
        "responses": { "200": { "content": {
            "application/json": { "schema": { "$ref": "#/components/schemas/Greeting" } }
        } } }
    });
    json!({
        "paths": { "/app/v1/api/greeting": { "post": operation } },
        "components": { "schemas": { "Greeting": {
            "type": "object",
            "properties": { "text": { "type": "string", "maxLength": 6 } },
            "additionalProperties": false,
            "required": ["text"],
        } } },
    })
}

fn capabilities() -> [Capability; 1] {
    [Capability {
        id: "proxy.hosts.read.v1".into(),
        scope: "proxyHosts".into(),
    }]
}

#[test]
fn operation_requires_declared_permission_and_matching_schemas() {
    let document = operation_document();
    assert!(read_operations(&document, &[], &capabilities()).is_empty());
    assert!(read_operations(&document, &["read".into()], &[]).is_empty());
    let operations = read_operations(&document, &["read".into()], &capabilities());
    let greeting = &operations["greeting"];
    let request = json!({"installationId":"demo"});
    assert!(greeting.request.is_valid(&request));
    assert!(greeting.access.valid_resource(&request));
    assert!(
        !greeting
            .access
            .valid_resource(&json!({"installationId":"/demo"}))
    );
    assert!(!greeting.request.is_valid(&json!({"other":"demo"})));
    assert!(greeting.response.is_valid(&json!({"text":"hello"})));
    assert!(!greeting.response.is_valid(&json!({"text":"too long"})));
    assert!(
        !greeting
            .response
            .is_valid(&json!({"text":"hello","unexpected":true}))
    );
}

#[test]
fn operation_rejects_unresolved_recursive_and_unsupported_schemas() {
    for schema in [
        json!({"$ref":"https://other.test/network.json"}),
        json!({"$ref":"local.json#/Schema"}),
        json!({"$ref":"#/components/schemas/Absent"}),
        json!({"$ref":"#/components/schemas/Greeting"}),
        json!({"type":"string","pattern":"hello"}),
        json!({"type":"unknown"}),
    ] {
        let mut document = operation_document();
        document["components"]["schemas"]["Greeting"] = schema;
        assert!(read_operations(&document, &["read".into()], &capabilities()).is_empty());
    }
}
