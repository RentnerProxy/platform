use super::*;
use marketplace_artifacts::digest;
use serde_json::json;
use std::fs;

const UID: u32 = 25001;

fn inventory(archive: Option<&str>) -> Inventory {
    let release = archive.map(|archive| {
        json!({
            "version": "1.0.1", "archiveSha256": archive, "manifestSha256": "b".repeat(64),
            "catalogRevision": 3,
        })
    });
    serde_json::from_value(json!({
        "app-fixture": {
            "appId": "rentnerproxy.fixture",
            "uid": UID,
            "generation": 1,
            "authorityRecorded": true,
            "storageClaimed": true,
            "active": release,
            "databaseProvisioned": archive.is_some(),
            "written": archive.map(|_| json!({
                "targetVersion": 1, "readVersions": [1], "writeVersions": [1], "migrations": []
            })),
            "desiredRunning": archive.is_some(),
            "pendingFence": false,
            "recoveryRequired": false,
            "providerDependenciesUnknown": false,
            "removal": "installed"
        }
    }))
    .unwrap()
}

fn member(kind: Kind, key: &str, bytes: &[u8]) -> Member {
    let identity = FileIdentity {
        sha256: digest(bytes),
        size_bytes: bytes.len() as u64,
    };
    if kind == Kind::Database {
        Member::database(key.into(), identity, 1_048_576)
    } else {
        Member::new(kind, key.into(), identity)
    }
}

fn data() -> &'static [u8] {
    br#"{"25001":[{"path":"greeting.json","mode":384,"contents":"e30="}]}"#
}

fn frame(header: &[u8], body: &[u8]) -> Vec<u8> {
    [
        MAGIC.as_slice(),
        &(header.len() as u32).to_be_bytes(),
        header,
        body,
    ]
    .concat()
}

#[test]
fn checks_archive_members_and_materializes_only_verified_contents() {
    let source = tempfile::tempdir().unwrap();
    let input = source.path().join("test-backup");
    let target = tempfile::tempdir().unwrap();
    let test_package = b"synthetic app package";
    let package_key = digest(test_package);
    let db_key = UID.to_string();
    let build_members = || {
        [
            (Kind::Data, "files", data()),
            (Kind::Checkpoint, "catalog", b"test checkpoint".as_slice()),
            (Kind::Package, package_key.as_str(), test_package.as_slice()),
            (
                Kind::Database,
                db_key.as_str(),
                b"test database archive".as_slice(),
            ),
        ]
        .map(|(kind, key, bytes)| {
            let member = member(kind, key, bytes);
            let path = member.destination(source.path());
            fs::write(&path, bytes).unwrap();
            (member, path)
        })
        .into_iter()
        .collect()
    };
    let mut bytes = Vec::new();
    write(inventory(Some(&package_key)), build_members(), &mut bytes).unwrap();
    fs::write(&input, &bytes).unwrap();
    let inspection = read(&input, None).unwrap();
    assert_eq!(inspection.digest, digest(&bytes));
    assert!(inspection.checkpoint.is_none());
    assert!(inspection.packages.is_empty());
    assert!(inspection.databases.is_empty());

    let restored = read(&input, Some(target.path())).unwrap();
    assert_eq!(restored.data[&UID].len(), 1);
    assert_eq!(
        fs::read(restored.checkpoint.unwrap()).unwrap(),
        b"test checkpoint"
    );
    assert_eq!(
        fs::read(&restored.packages[&package_key]).unwrap(),
        test_package
    );
    assert_eq!(
        fs::read(&restored.databases[&UID]).unwrap(),
        b"test database archive"
    );

    *bytes.last_mut().unwrap() ^= 1;
    fs::write(&input, bytes).unwrap();
    assert!(read(&input, None).is_err());

    let altered: Vec<_> = build_members();
    fs::write(&altered[2].1, b"modified app package!").unwrap();
    assert!(write(inventory(Some(&package_key)), altered, Vec::new()).is_err());
}

#[test]
fn rejects_bad_framing_and_inconsistent_inventory() {
    let source = tempfile::tempdir().unwrap();
    let input = source.path().join("test-backup");
    let mut header = Header {
        format_version: 2,
        installations: inventory(None),
        members: vec![member(Kind::Data, "files", data())],
    };
    let encode = |header: &Header| serde_json::to_vec(header).unwrap();
    let valid = frame(&encode(&header), data());
    fs::write(&input, &valid).unwrap();
    assert!(read(&input, None).is_ok());

    let reject = |bytes: &[u8]| {
        fs::write(&input, bytes).unwrap();
        assert!(read(&input, None).is_err());
    };
    reject(&valid[..PREFIX as usize]);
    reject(&valid[..valid.len() - 1]);
    reject(&[valid.as_slice(), &[0]].concat());
    reject(&[b"UNKNOWN!".as_slice(), &valid[MAGIC.len()..]].concat());
    let encoded = encode(&header);
    let duplicate = [br#"{"formatVersion":2,"#.as_slice(), &encoded[1..]].concat();
    fs::write(&input, frame(&duplicate, data())).unwrap();
    assert_eq!(
        read(&input, None).err().unwrap().to_string(),
        "Duplicate JSON member"
    );
    reject(&frame(&encode(&header), &vec![b' '; data().len()]));

    header.format_version = 1;
    reject(&frame(&encode(&header), data()));
    header.format_version = 2;
    header.members[0].key = "unexpected".into();
    reject(&frame(&encode(&header), data()));
    header.members[0] = member(Kind::Data, "files", b"{}");
    reject(&frame(&encode(&header), b"{}"));

    let unexpected = br#"{"25001":[],"25002":[]}"#;
    header.members[0] = member(Kind::Data, "files", unexpected);
    reject(&frame(&encode(&header), unexpected));

    for invalid in [b"[]".as_slice(), br#"{"025001":[]}"#, br#"{"x":[]}"#] {
        header.members[0] = member(Kind::Data, "files", invalid);
        reject(&frame(&encode(&header), invalid));
    }
}

#[test]
fn requires_exact_package_and_database_members_within_the_byte_budget() {
    let package = b"test package";
    let key = digest(package);
    let mut header = Header {
        format_version: 2,
        installations: inventory(Some(&key)),
        members: vec![
            member(Kind::Data, "files", data()),
            member(Kind::Checkpoint, "catalog", b"checkpoint"),
            member(Kind::Package, &key, package),
            member(Kind::Database, &UID.to_string(), b"database"),
        ],
    };
    header.validate(500).unwrap();
    assert_eq!(
        remaining_payload(&header.members).unwrap(),
        MAX_BYTES
            - header
                .members
                .iter()
                .map(|member| member.bytes)
                .sum::<u64>()
    );
    header.members[3].bytes = database::MAX_ARCHIVE;
    assert!(remaining_payload(&header.members).is_err());
    assert!(header.validate(500).is_err());
    header.members[3].bytes = 0;
    assert!(header.validate(500).is_err());
    header.members[3] = member(Kind::Database, "25002", b"database");
    assert!(header.validate(500).is_err());
    header.members[3] = member(Kind::Database, &UID.to_string(), b"database");
    header.members[3].allocation_bytes = None;
    assert!(header.validate(500).is_err());
    header.members[3].allocation_bytes = Some(0);
    assert!(header.validate(500).is_err());
    header.members[3].allocation_bytes = Some(1_048_576);
    header.members.swap(1, 2);
    assert!(header.validate(500).is_err());
    header.members.swap(1, 2);
    header.members.remove(1);
    assert!(header.validate(500).is_err());
}
