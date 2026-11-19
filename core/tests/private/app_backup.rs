use super::{Snapshot, app_roots, process, validate_snapshot};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, chown},
};

#[test]
fn missing_data_requires_an_existing_verified_installation_owner() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let uid = 25001;
    let inventory = json!({"kiri":{"uid":uid,"appId":"app.kiri","generation":1,"removal":"installed","databaseProvisioned":false,"written":null}});
    assert!(app_roots(directory.path(), &inventory, Some(".app-restore-fixture")).is_err());
    let parent = directory.path().join(uid.to_string());
    fs::create_dir(&parent).unwrap();
    chown(&parent, Some(0), Some(uid)).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o710)).unwrap();
    let owner = parent.join(".manager-owner");
    fs::write(&owner, b"app.wrong\nkiri\n").unwrap();
    fs::set_permissions(&owner, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(app_roots(directory.path(), &inventory, Some(".app-restore-fixture")).is_err());
    fs::set_permissions(&owner, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&owner, b"app.kiri\nkiri\n").unwrap();
    fs::set_permissions(&owner, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(app_roots(directory.path(), &inventory, None).is_err());
    let targets = app_roots(directory.path(), &inventory, Some(".app-restore-fixture")).unwrap();
    assert_eq!(targets[&uid], parent.join("data"));
    assert!(!targets[&uid].exists());

    let data = parent.join("data");
    std::os::unix::fs::symlink(directory.path(), &data).unwrap();
    assert_eq!(
        app_roots(directory.path(), &inventory, None)
            .unwrap_err()
            .to_string(),
        "Unsafe installation data directory"
    );
    fs::remove_file(&data).unwrap();
    fs::create_dir(&data).unwrap();
    chown(&data, Some(uid), Some(uid)).unwrap();
    fs::set_permissions(&data, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        app_roots(directory.path(), &inventory, None).unwrap(),
        targets
    );

    let orphan = directory.path().join("25002");
    fs::create_dir(&orphan).unwrap();
    assert_eq!(
        app_roots(directory.path(), &inventory, None)
            .unwrap_err()
            .to_string(),
        "Untracked installation data"
    );
}

#[test]
fn inventory_requires_unique_owned_data_and_durable_retirement() {
    let live = json!({
        "uid": 25180,
        "generation": 7,
        "authorityRecorded": true,
        "removal": "installed",
        "databaseProvisioned": false,
        "written": null
    });
    let purged = json!({
        "uid": 25181,
        "generation": 10,
        "authorityRecorded": false,
        "removal": "purged",
        "databaseProvisioned": false,
        "written": null
    });
    let snapshot = json!({
        "formatVersion": 1,
        "installations": {"live":live, "purged":purged},
        "data": {"25180":[]}
    });
    let check =
        |snapshot: Value| validate_snapshot(&serde_json::from_value::<Snapshot>(snapshot).unwrap());
    check(snapshot.clone()).unwrap();
    let file = tempfile::NamedTempFile::new().unwrap();
    let inspect = [
        "inspect".to_owned(),
        file.path().to_str().unwrap().to_owned(),
    ];
    fs::write(file.path(), serde_json::to_vec(&snapshot).unwrap()).unwrap();
    process(&inspect).unwrap();
    fs::write(file.path(), b"{incomplete").unwrap();
    assert!(process(&inspect).is_err());

    for (field, value) in [
        ("uid", json!(19999)),
        ("uid", json!(25181)),
        ("generation", Value::Null),
        ("authorityRecorded", json!("true")),
        ("removal", json!("removing")),
        ("databaseProvisioned", json!(true)),
        ("written", json!({})),
    ] {
        let mut changed = snapshot.clone();
        changed["installations"]["live"][field] = value;
        assert!(check(changed).is_err(), "{field}");
    }
    for (field, value) in [
        ("data", json!({})),
        ("data", json!({"25180":[], "25181":[]})),
        ("data", json!({"25180":[], "25182":[]})),
        ("installations", json!({})),
        ("installations", json!([])),
        ("formatVersion", json!(2)),
    ] {
        let mut changed = snapshot.clone();
        changed[field] = value;
        assert!(check(changed).is_err(), "{field}");
    }
}
