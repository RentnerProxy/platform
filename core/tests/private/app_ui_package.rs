use super::*;
use serde_json::json;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, chown, symlink},
};

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
    assert!(valid_relative_path(&"a".repeat(240)));
    assert!(!valid_relative_path(&"a".repeat(241)));
}

#[test]
fn open_ui_files_are_bounded_and_do_not_follow_links() {
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

    assert!(read_beneath(&root, "./nested/index.html", 5).is_err());
    assert!(read_beneath(&root, "nested", 5).is_err());
    assert!(read_beneath(&root, "missing", 5).is_err());
    let asset = temp.path().join("asset.html");
    fs::write(&asset, b"hello").unwrap();
    fs::set_permissions(&asset, fs::Permissions::from_mode(0o664)).unwrap();
    assert!(read_beneath(&root, "asset.html", 5).is_err());
    fs::set_permissions(&asset, fs::Permissions::from_mode(0o644)).unwrap();
    chown(&asset, Some(20_000), None).unwrap();
    assert!(read_beneath(&root, "asset.html", 5).is_err());

    let nested = temp.path().join("nested");
    fs::remove_file(temp.path().join("hard.html")).unwrap();
    fs::set_permissions(&nested, fs::Permissions::from_mode(0o775)).unwrap();
    assert!(read_beneath(&root, "nested/index.html", 5).is_err());
    fs::set_permissions(&nested, fs::Permissions::from_mode(0o755)).unwrap();
    chown(&nested, Some(20_000), None).unwrap();
    assert!(read_beneath(&root, "nested/index.html", 5).is_err());
}

fn staged_ui() -> (tempfile::TempDir, StagedPackage) {
    let temp = tempfile::tempdir_in("/run").unwrap();
    fs::create_dir(temp.path().join("ui")).unwrap();
    fs::write(temp.path().join("ui/index.html"), b"fixture").unwrap();
    let package = StagedPackage {
        directory: temp.path().to_path_buf(),
        manifest: json!({
            "id": "example.app",
            "display": {"name": "Example"},
            "ui": {"entrypoint": "ui/index.html", "slots": ["apps"]},
            "permissions": ["read"],
            "capabilities": [{"id": "proxy.hosts.read.v1", "scope": "proxyHosts"}],
        }),
        archive_sha256: "a".repeat(64),
        manifest_sha256: "b".repeat(64),
        catalog_revision: 1,
    };
    (temp, package)
}

#[test]
fn package_load_combines_manifest_and_openapi_metadata() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let (temp, mut staged) = staged_ui();
    staged.manifest["api"] = json!("api.json");
    let mut document = operation_document();
    document["openapi"] = json!("3.1.0");
    document["x-rentnerproxy-ui"] = json!({
        "routes": ["settings", "overview"], "dialogs": ["edit"], "events": ["changed"],
    });
    let presentation = json!({"formatVersion": 1, "pages": []});
    document["x-rentnerproxy-native-ui"] = presentation.clone();
    fs::write(temp.path().join("api.json"), document.to_string()).unwrap();
    let package = Package::load(&staged, "demo".into(), 7, 20_000)
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::to_value(package.metadata).unwrap(),
        json!({
            "appId": "example.app", "installationId": "demo", "generation": 7, "uid": 20_000,
            "archiveSha256": "a".repeat(64), "name": "Example", "entrypoint": "ui/index.html",
            "slots": ["apps"], "permissionKeys": ["read"], "routes": ["overview", "settings"],
            "dialogs": ["edit"], "events": ["changed"], "nativePresentation": presentation,
        })
    );
    assert_eq!(package.operations.keys().collect::<Vec<_>>(), &["greeting"]);
}

#[test]
fn native_presentation_stays_within_its_metadata_budget() {
    assert!(read_native_presentation(&json!({})).is_none());
    assert!(read_native_presentation(&json!({"x-rentnerproxy-native-ui": []})).is_none());
    let oversized = json!({
        "x-rentnerproxy-native-ui": {"label": "x".repeat(MAX_NATIVE_PRESENTATION_BYTES)}
    });
    assert!(read_native_presentation(&oversized).is_none());
}

#[test]
fn full_app_inventory_fits_with_maximum_presentation_metadata() {
    let ids = (0..MAX_UI_ENTRIES)
        .map(|index| format!("{}{:02}", "x".repeat(62), index))
        .collect::<Vec<_>>();
    let descriptor = json!({"label": "x".repeat(MAX_NATIVE_PRESENTATION_BYTES - 12)});
    assert_eq!(
        serde_json::to_vec(&descriptor).unwrap().len(),
        MAX_NATIVE_PRESENTATION_BYTES
    );
    let metadata = Metadata {
        app_id: format!("{}.{}", "x".repeat(32), "x".repeat(64)),
        installation_id: ids[0].clone(),
        generation: super::super::MAX_GENERATION,
        uid: 65_000,
        archive_sha256: "a".repeat(64),
        name: "\u{10000}".repeat(120),
        entrypoint: format!("ui/{}.html", "x".repeat(232)),
        slots: ["navigation", "proxyHostTab", "dashboardWidget", "search"]
            .map(String::from)
            .to_vec(),
        permission_keys: (0..64)
            .map(|index| format!("{}{:02}", "x".repeat(30), index))
            .collect(),
        routes: ids.clone(),
        dialogs: ids.clone(),
        events: ids,
        native_presentation: Some(descriptor),
    };
    let inventory = serde_json::to_vec(&vec![&metadata; 256]).unwrap();
    assert!(inventory.len() <= super::super::MAX_LIST_RESPONSE_BYTES);
}

#[test]
fn package_load_defaults_without_ui_declarations() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let (temp, mut staged) = staged_ui();
    let original = staged.manifest.clone();
    staged.manifest.as_object_mut().unwrap().remove("ui");
    assert!(
        Package::load(&staged, "demo".into(), 1, 20_000)
            .unwrap()
            .is_none()
    );
    staged.manifest = original;
    let verify_defaults = |staged: &StagedPackage| {
        let package = Package::load(staged, "demo".into(), 1, 20_000)
            .unwrap()
            .unwrap();
        assert_eq!(package.asset("index.html").unwrap(), b"fixture");
        assert_eq!(package.metadata.routes, ["overview"]);
        assert!(package.metadata.dialogs.is_empty());
        assert!(package.metadata.events.is_empty());
        assert!(package.operations.is_empty());
    };
    verify_defaults(&staged);

    staged.manifest["api"] = json!("api.json");
    fs::write(temp.path().join("api.json"), r#"{"openapi":"3.1.0"}"#).unwrap();
    verify_defaults(&staged);
}

#[test]
fn package_load_reports_an_unusable_declared_api() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let (temp, mut staged) = staged_ui();
    staged.manifest["api"] = json!("api.json");
    let load = || Package::load(&staged, "demo".into(), 1, 20_000);
    assert_eq!(load().err().unwrap().kind(), io::ErrorKind::NotFound);
    for document in [
        r#"{"openapi":"3.0.3","x-rentnerproxy-ui":{"routes":["settings"]}}"#,
        r#"{"openapi":"3.1.0","openapi":"3.1.0","x-rentnerproxy-ui":{"routes":["settings"]}}"#,
    ] {
        fs::write(temp.path().join("api.json"), document).unwrap();
        assert_eq!(load().err().unwrap().kind(), io::ErrorKind::InvalidData);
    }
}

#[test]
fn package_load_rejects_invalid_ui_metadata_and_staging_directories() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let (temp, mut staged) = staged_ui();
    let original = staged.manifest.clone();
    for (pointer, invalid_value) in [
        ("/ui/entrypoint", json!(false)),
        ("/ui/entrypoint", json!("index.html")),
        ("/ui/entrypoint", json!("ui/index.js")),
        ("/ui/entrypoint", json!("ui/missing.html")),
        ("/ui/slots", json!("apps")),
        ("/permissions", json!([false])),
        ("/capabilities", json!(["proxy.hosts.read.v1"])),
        ("/display/name", Value::Null),
        ("/id", Value::Null),
    ] {
        staged.manifest = original.clone();
        *staged.manifest.pointer_mut(pointer).unwrap() = invalid_value;
        assert!(
            Package::load(&staged, "demo".into(), 1, 20_000).is_err(),
            "{pointer}"
        );
    }

    staged.manifest = original;
    staged.manifest["api"] = json!("api.json");
    let routes: Vec<_> = (0..MAX_UI_ENTRIES).map(|i| format!("route-{i}")).collect();
    let api = temp.path().join("api.json");
    for declarations in [
        json!({"unexpected": []}),
        json!({"routes": "overview"}),
        json!({"dialogs": ["edit", "edit"]}),
        json!({"events": ["Not a valid ID"]}),
        json!({"routes": routes}),
        json!({"events": vec!["changed"; MAX_UI_ENTRIES + 1]}),
    ] {
        let document = json!({"openapi":"3.1.0", "x-rentnerproxy-ui": declarations});
        fs::write(&api, document.to_string()).unwrap();
        assert!(
            Package::load(&staged, "demo".into(), 1, 20_000).is_err(),
            "{declarations}"
        );
    }
    let mut routes = routes;
    routes[0] = "overview".into();
    let document = json!({"openapi":"3.1.0", "x-rentnerproxy-ui": {"routes":routes}});
    fs::write(&api, document.to_string()).unwrap();
    let package = Package::load(&staged, "demo".into(), 1, 20_000)
        .unwrap()
        .unwrap();
    assert_eq!(package.metadata.routes, routes);

    let alias = temp.path().join("alias");
    symlink(temp.path(), &alias).unwrap();
    assert!(open_package(&alias).is_err());
    assert!(open_package(Path::new("relative")).is_err());
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o770)).unwrap();
    assert!(Package::load(&staged, "demo".into(), 1, 20_000).is_err());
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
fn greeting_operations_enforce_the_published_pattern() {
    let greeting_ref = json!({"$ref": "#/components/schemas/Greeting"});
    let operation = |id: &str, permission: &str, request: &Value| {
        json!({
            "post": {
                "operationId": id,
                "x-rentnerproxy-access": { "permissionKey": permission },
                "requestBody": { "content": { "application/json": { "schema": request } } },
                "responses": { "200": { "content": {
                    "application/json": { "schema": greeting_ref }
                } } }
            }
        })
    };
    let document = json!({
        "paths": {
            "/app/v1/api/get-greeting": operation(
                "get-greeting", "greeting-read",
                &json!({"type": "object", "additionalProperties": false}),
            ),
            "/app/v1/api/save-greeting": operation("save-greeting", "greeting-write", &greeting_ref),
        },
        "components": { "schemas": { "Greeting": {
            "type": "object",
            "required": ["greeting"],
            "properties": { "greeting": {
                "type": "string",
                "minLength": 1,
                "maxLength": 120,
                "pattern": r"^[^\s\x00-\x1f\x7f-\x9f](?:[^\x00-\x1f\x7f-\x9f]*[^\s\x00-\x1f\x7f-\x9f])?$",
            } },
            "additionalProperties": false,
        } } }
    });
    let operations = read_operations(
        &document,
        &["greeting-read".into(), "greeting-write".into()],
        &[],
    );
    assert_eq!(operations.len(), 2);
    let get = &operations["get-greeting"];
    let save = &operations["save-greeting"];
    assert!(get.request.is_valid(&json!({})));
    assert!(!get.request.is_valid(&json!({"greeting": "Hallo"})));
    for validator in [&get.response, &save.request, &save.response] {
        for greeting in [String::from("Grüße aus Obernburg!"), "ä".repeat(120)] {
            assert!(validator.is_valid(&json!({"greeting": greeting})));
        }
        for invalid in [
            json!({"greeting": ""}),
            json!({"greeting": " Hallo"}),
            json!({"greeting": "Hallo\u{00a0}"}),
            json!({"greeting": "Hal\nlo"}),
            json!({"greeting": "Hal\u{0085}lo"}),
            json!({"greeting": "ä".repeat(121)}),
            json!({"greeting": "Hallo", "unexpected": true}),
        ] {
            assert!(!validator.is_valid(&invalid), "{invalid}");
        }
    }
}

#[test]
fn operation_rejects_unresolved_recursive_and_unsupported_schemas() {
    for schema in [
        json!({"$ref":"https://other.test/network.json"}),
        json!({"$ref":"local.json#/Schema"}),
        json!({"$ref":"#/components/schemas/Absent"}),
        json!({"$ref":"#/components/schemas/Greeting"}),
        json!({"type":"object","patternProperties":{"^x":true}}),
        json!({"type":"unknown"}),
    ] {
        let mut document = operation_document();
        document["components"]["schemas"]["Greeting"] = schema;
        assert!(read_operations(&document, &["read".into()], &capabilities()).is_empty());
    }
}

#[test]
fn operation_requires_a_matching_post_and_json_contracts() {
    const POST: &str = "/paths/~1app~1v1~1api~1greeting/post";
    let permissions = ["read".into()];
    for (field, invalid_value) in [
        ("operationId", json!("another-operation")),
        (
            "x-rentnerproxy-access",
            json!({"permissionKey":"read", "resource":null}),
        ),
        (
            "x-rentnerproxy-access",
            json!({"permissionKey":"read", "unexpected":true}),
        ),
        (
            "requestBody",
            json!({"content":{"text/plain":{"schema":true}}}),
        ),
        (
            "responses",
            json!({"201":{"content":{"application/json":{"schema":true}}}}),
        ),
    ] {
        let mut document = operation_document();
        document.pointer_mut(POST).unwrap()[field] = invalid_value;
        assert!(
            read_operations(&document, &permissions, &capabilities()).is_empty(),
            "{field}"
        );
    }

    let mut document = operation_document();
    let post = document.pointer(POST).unwrap().clone();
    document["paths"] = json!({
        "/unrelated": {"post": post},
        "/app/v1/api/not/an/id": {"post":post},
        "/app/v1/api/greeting": {"get": post},
    });
    assert!(read_operations(&document, &permissions, &capabilities()).is_empty());
    assert!(read_operations(&json!({}), &permissions, &capabilities()).is_empty());
}

#[test]
fn operation_uses_locally_referenced_request_and_response_objects() {
    let mut document = operation_document();
    let post = &mut document["paths"]["/app/v1/api/greeting"]["post"];
    let request = post["requestBody"].take();
    let response = post["responses"]["200"].take();
    post["requestBody"] = json!({"$ref":"#/components/requestBodies/Greeting"});
    post["responses"]["200"] = json!({"$ref":"#/components/responses/%47reeting"});
    document["components"]["requestBodies"] = json!({
        "Greeting": {"$ref":"#/components/requestBodies/Body"},
        "Body": request,
    });
    document["components"]["responses"] = json!({"Greeting":response});
    let operations = read_operations(&document, &["read".into()], &capabilities());
    let greeting = &operations["greeting"];
    assert!(greeting.request.is_valid(&json!({"installationId":"demo"})));
    assert!(!greeting.request.is_valid(&json!({"installationId":1})));
    assert!(greeting.response.is_valid(&json!({"text":"hello"})));
    assert!(!greeting.response.is_valid(&json!({"text":"too long"})));
}

#[test]
fn operation_rejects_unsupported_or_unresolved_object_references() {
    for reference in [
        json!(true),
        json!("https://other.test/openapi.json#/components/responses/Greeting"),
        json!("other.json#/components/responses/Greeting"),
        json!("#/components/responses/Missing"),
        json!("#/components/responses/Invalid~2"),
        json!("#/components/responses/%GG"),
        json!("#/components/responses/%FF"),
        json!("#/components/responses/Number"),
        json!("#/components/responses/First"),
        json!(format!("#/{}", "x".repeat(MAX_REFERENCE_BYTES))),
    ] {
        let mut document = operation_document();
        document["paths"]["/app/v1/api/greeting"]["post"]["responses"]["200"] =
            json!({"$ref": reference});
        document["components"]["responses"] = json!({
            "First":{"$ref":"#/components/responses/Second"},
            "Second":{"$ref":"#/components/responses/First"},
            "Number":1,
        });
        assert!(read_operations(&document, &["read".into()], &capabilities()).is_empty());
    }
}

#[test]
fn operation_scope_requires_the_declared_capability_and_a_valid_resource_id() {
    let permissions = ["read".into()];
    let capabilities = capabilities();
    let mut document = operation_document();
    let access = &mut document["paths"]["/app/v1/api/greeting"]["post"]["x-rentnerproxy-access"];
    access["resource"]["capability"]["scope"] = json!("installations");
    assert!(read_operations(&document, &permissions, &capabilities).is_empty());

    for field in ["", "_resource", "resource-id", &"r".repeat(65)] {
        let mut document = operation_document();
        document["paths"]["/app/v1/api/greeting"]["post"]["x-rentnerproxy-access"]["resource"]["resourceIdField"] =
            json!(field);
        assert!(
            read_operations(&document, &permissions, &capabilities).is_empty(),
            "{field}"
        );
    }
    let operations = read_operations(&operation_document(), &permissions, &capabilities);
    let greeting = &operations["greeting"];
    for payload in [
        json!({}),
        json!({"installationId":1}),
        json!({"installationId":"Demo"}),
    ] {
        assert!(!greeting.access.valid_resource(&payload));
    }

    let mut document = operation_document();
    document["paths"]["/app/v1/api/greeting"]["post"]["x-rentnerproxy-access"] =
        json!({"permissionKey":"read"});
    let operations = read_operations(&document, &permissions, &[]);
    assert!(operations["greeting"].access.valid_resource(&json!({})));
}

#[test]
fn operation_count_is_bounded_without_counting_unrelated_paths() {
    let mut paths = Map::new();
    for index in 0..=MAX_ENTRIES {
        let id = format!("read-{index}");
        paths.insert(
            format!("{APP_API_PREFIX}{id}"),
            json!({
                "post": {
                    "operationId": id,
                    "x-rentnerproxy-access": {"permissionKey": "read"},
                    "requestBody": {"content":{"application/json":{"schema":true}}},
                    "responses": {"200":{"content":{"application/json":{"schema":true}}}},
                },
            }),
        );
    }
    let permissions = ["read".into()];
    let extra = paths
        .remove(&format!("{APP_API_PREFIX}read-{MAX_ENTRIES}"))
        .unwrap();
    paths.insert("/unrelated".into(), extra.clone());
    let mut document = json!({"paths":paths});
    assert_eq!(
        read_operations(&document, &permissions, &[]).len(),
        MAX_ENTRIES
    );
    document["paths"][format!("{APP_API_PREFIX}read-{MAX_ENTRIES}")] = extra;
    assert!(read_operations(&document, &permissions, &[]).is_empty());
}

#[test]
fn expands_supported_schema_shapes_and_local_references() {
    let document = json!({"components":{"schemas":{
        "Tag": {"enum":["red", "blue"]},
        "Alias": {"$ref":"#/components/schemas/Tag"},
    }}});
    let schema = json!({
        "title": "Tagged values", "description":"Example", "default":[], "examples":[],
        "example":[], "deprecated":false,
        "type":"array", "minItems":2, "maxItems":3,
        "prefixItems":[{"$ref":"#/components/schemas/Alias"}],
        "items":{"allOf":[
            {"type":"object", "additionalProperties": {"type":"number", "maximum":10}},
            {"anyOf":[
                {"const":{"values":[1,2]}},
                {"oneOf":[{"required":["x"]}, {"required":["y"]}]},
            ]},
        ]},
    });
    let validator = compile(&document, &schema).unwrap();
    assert!(validator.is_valid(&json!(["red", {"x": 10}])));
    for invalid in [
        json!(["green", {"x":10}]),
        json!(["red", {"x":11}]),
        json!(["red", {"x":10, "y":10}]),
        json!(["red"]),
    ] {
        assert!(!validator.is_valid(&invalid), "{invalid}");
    }
    assert!(
        !compile(&document, &json!(false))
            .unwrap()
            .is_valid(&json!(null))
    );
}

#[test]
fn rejects_malformed_schemas_and_bounds_expansion() {
    let document = json!({"components":{"schemas":{
        "First": {"$ref":"#/components/schemas/Second"},
        "Second": {"$ref":"#/components/schemas/First"},
    }}});
    for schema in [
        json!(null),
        json!({"properties": []}),
        json!({"items": 1}),
        json!({"anyOf": {}}),
        json!({"allOf": [null]}),
        json!({"required": "field"}),
        json!({"enum": vec!["value"; MAX_ENTRIES + 1]}),
        json!({"$ref": 1}),
        json!({"$ref": "#/definitions/Tag"}),
        json!({"$ref": "#/components/schemas/"}),
        json!({"$ref": "#/components/schemas/First/Second"}),
        json!({"$ref": "#/components/schemas/F%69rst"}),
        json!({"$ref": "#/components/schemas/First", "type":"string"}),
        json!({"$ref": "#/components/schemas/First"}),
        json!({"const": {"value":"x".repeat(MAX_SCHEMA_BYTES)}}),
    ] {
        assert!(
            compile(&document, &schema).is_none(),
            "invalid schema accepted"
        );
    }

    let depth_limit = (0..MAX_SCHEMA_DEPTH).fold(json!(true), |child, _| json!({"items":child}));
    assert!(compile(&document, &depth_limit).is_some());
    assert!(compile(&document, &json!({"items":depth_limit})).is_none());

    let properties: Map<String, Value> = (0..MAX_SCHEMA_NODES - 1)
        .map(|i| (format!("field-{i}"), json!(true)))
        .collect();
    let mut node_limit = json!({"properties":properties});
    assert!(compile(&document, &node_limit).is_some());
    node_limit["properties"]["extra"] = json!(true);
    assert!(compile(&document, &node_limit).is_none());
}

#[test]
fn rejects_invalid_and_over_budget_patterns() {
    let document = json!({});
    for pattern in [
        json!(1),
        json!("["),
        json!("(?<=a)b"),
        json!("^(?:[a-z0-9]{8}-){4096}$"),
        json!("a".repeat(MAX_PATTERN_BYTES + 1)),
    ] {
        let schema = json!({"type": "string", "pattern": pattern});
        assert!(compile(&document, &schema).is_none(), "{pattern}");
    }

    let pattern = json!({"pattern": "^hello$"});
    let mut patterns = vec![pattern.clone(); MAX_SCHEMA_PATTERNS];
    assert!(compile(&document, &json!({"allOf": patterns})).is_some());
    patterns.push(pattern);
    assert!(compile(&document, &json!({"allOf": patterns})).is_none());
}
