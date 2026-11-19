use super::*;
#[path = "app_manager/lifecycle.rs"]
mod lifecycle;
#[tokio::test]
#[ignore = "requires the isolated Linux lifecycle fixture and a dedicated writable appliance tmpfs"]
async fn privileged_signed_lifecycle() {
    lifecycle::exercise().await;
}
use crate::app_manager::journal::compatible;

#[test]
fn installation_id_cannot_select_a_path_or_escape_an_identity() {
    for id in [
        "",
        "../data",
        "/id",
        "two\nids",
        "-id",
        "root:field",
        "ü",
        "A0",
    ] {
        assert!(!valid_id(id));
    }
    assert!(!valid_id(&"a".repeat(65)));
    assert!(valid_id("instance_1-test"));
}

#[test]
fn data_changes_preserve_every_possible_written_version_or_require_recovery() {
    let manifest =
        json!({"targetVersion":2.0,"readVersions":[1,2.0,3],"writeVersions":[2,3],"migrations":[]});
    let source = read_data(&manifest).unwrap();
    let mut target = source.clone();
    assert!(compatible(None, None));
    assert!(compatible(None, Some(&source)));
    assert!(compatible(Some(&source), Some(&target)));
    target.write_versions.retain(|v| *v != 3);
    assert!(!compatible(Some(&source), Some(&target)));
    target = source.clone();
    target.read_versions.retain(|v| *v != 3);
    assert!(!compatible(Some(&source), Some(&target)));
    target.target_version = 3;
    assert!(!compatible(Some(&source), Some(&target)));
    assert!(!compatible(Some(&source), None));
    target.migrations = vec![json!({"fromVersion":0,"toVersion":3,"path":"migrations/start.sql"})];
    assert!(!compatible(None, Some(&target)));
}

#[test]
fn control_denies_undeclared_fields_and_defaults_new_authority_to_empty() {
    let cmd =
        serde_json::from_value::<Command>(json!({"action":"activate","installationId":"test"}))
            .unwrap();
    assert!(matches!(cmd,Command::Activate{grants,..} if grants.is_empty()));
    for field in [
        "executable",
        "uid",
        "generation",
        "databaseUrlFile",
        "socket",
    ] {
        let mut request = json!({"action":"start","installationId":"test"});
        request[field] = "override".into();
        assert!(serde_json::from_value::<Command>(request).is_err());
    }
}

#[test]
fn interrupted_generation_and_uid_reservations_survive_single_owner_reopen() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let tmp = tempfile::tempdir_in("/root").unwrap();
    let dir = tmp.path().join("manager");
    let mut journal = Journal::open(&dir).unwrap();
    assert!(Journal::open(&dir).is_err());
    let slot = Slot {
        app_id: "fixture.one".into(),
        uid: 20000,
        generation: 3,
        pending_fence: true,
        recovery_required: true,
        ..Default::default()
    };
    journal.save("install", slot).unwrap();
    let writer = journal.writer(20000).unwrap();
    assert!(journal.writer(20000).is_err());
    drop(journal);
    let reopened = Journal::open(&dir).unwrap();
    let state = reopened.slot("install").unwrap();
    assert_eq!(state.generation, 3);
    assert!(state.pending_fence && state.recovery_required);
    assert!(reopened.writer(20000).is_err());
    drop(writer);
    assert!(reopened.writer(20000).is_ok());
    drop(reopened);
    std::fs::write(dir.join("journal.json"), b"{").unwrap();
    assert!(Journal::open(&dir).is_err());
}

#[tokio::test]
async fn native_gateway_requires_expected_peer_and_a_confirmed_transition() {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixListener,
    };
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("web.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let uid = unsafe { libc::geteuid() };
    let gateway = Gateway::fixture(path.clone(), uid);
    let wrong_peer = Gateway::fixture(path, uid.wrapping_add(1));
    assert!(wrong_peer.post("renew", json!({})).await.is_err());
    let web = tokio::spawn(async move {
        for status in ["204 No Content", "409 Conflict"] {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"{}") {
                let byte = stream.read_u8().await.unwrap();
                request.push(byte);
                assert!(request.len() < 2048);
            }
            let head = String::from_utf8(request).unwrap().to_lowercase();
            assert!(head.starts_with("post /internal/v1/app-generations/renew http/1.1"));
            assert!(head.contains("authorization: bearer fixture"));
            stream
                .write_all(
                    format!("HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                        .as_bytes(),
                )
                .await
                .unwrap();
        }
    });
    gateway.post("renew", json!({})).await.unwrap();
    assert!(gateway.post("renew", json!({})).await.is_err());
    web.await.unwrap();
}

#[tokio::test]
async fn dependency_block_and_separate_purge_keep_the_uid_reserved() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let temp = tempfile::tempdir_in("/root").unwrap();
    let journal = Journal::open(&temp.path().join("manager")).unwrap();
    let mut manager = Manager {
        config: temp.path().join("offline"),
        journal,
        gateway: Gateway::fixture(temp.path().join("absent.sock"), 0),
        running: BTreeMap::new(),
    };
    let slot = Slot {
        app_id: "example.test".into(),
        uid: 59997,
        provider_dependencies_unknown: true,
        ..Default::default()
    };
    manager.journal.save("example", slot.clone()).unwrap();
    assert!(manager.remove("example").await.is_err());
    assert!(manager.purge("example").await.is_err());
    assert_eq!(
        manager.journal.slot("example").unwrap().removal,
        Removal::Installed
    );
    manager
        .journal
        .save(
            "example",
            Slot {
                provider_dependencies_unknown: false,
                ..slot
            },
        )
        .unwrap();
    manager.remove("example").await.unwrap();
    assert_eq!(
        manager.journal.slot("example").unwrap().removal,
        Removal::Removed
    );
    manager.purge("example").await.unwrap();
    manager.purge("example").await.unwrap();
    let final_state = manager.journal.slot("example").unwrap();
    assert_eq!(final_state.removal, Removal::Purged);
    assert_eq!(final_state.uid, 59997);
    assert!(
        manager
            .execute(Command::Start {
                installation_id: "example".into()
            })
            .await
            .is_err()
    );
}
