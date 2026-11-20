use std::os::unix::fs::MetadataExt;

use std::process::ExitCode;

use super::{Ownership, Publication, publish, run_write_bootstrap_state};

#[test]
fn bootstrap_writer_rejects_invalid_operations_before_opening_state() {
    for command in [
        &[][..],
        &["secrets-v1.json", "unknown"],
        &["secrets-v1.json", "create", "unexpected"],
        &["../secrets-v1.json", "replace"],
    ] {
        assert_eq!(
            run_write_bootstrap_state(command.iter().map(|value| (*value).to_owned())),
            ExitCode::FAILURE
        );
    }
}

#[test]
fn publishes_without_clobber_and_replaces_only_on_request() {
    let temporary = tempfile::tempdir().unwrap();
    let directory = temporary.path();
    let destination = directory.join("state");
    let directory_metadata = directory.metadata().unwrap();
    let ownership = Ownership {
        uid: directory_metadata.uid(),
        gid: directory_metadata.gid(),
        mode: 0o400,
    };
    publish(
        directory,
        &destination,
        b"first",
        ownership,
        Publication::Create,
    )
    .unwrap();
    assert_eq!(destination.metadata().unwrap().mode() & 0o7777, 0o400);
    assert!(
        publish(
            directory,
            &destination,
            b"second",
            ownership,
            Publication::Create
        )
        .is_err()
    );
    assert_eq!(std::fs::read(&destination).unwrap(), b"first");
    publish(
        directory,
        &destination,
        b"second",
        ownership,
        Publication::Replace,
    )
    .unwrap();
    assert_eq!(std::fs::read(&destination).unwrap(), b"second");
    assert_eq!(std::fs::read_dir(directory).unwrap().count(), 1);
}

#[test]
fn app_owned_destination_is_link_replaced_without_writing_to_its_target() {
    let temporary = tempfile::tempdir().unwrap();
    let directory = temporary.path();
    let staging = directory.join("staging");
    let data = directory.join("data");
    std::fs::create_dir(&staging).unwrap();
    std::fs::create_dir(&data).unwrap();
    let sentinel = directory.join("sentinel");
    std::fs::write(&sentinel, b"intact").unwrap();
    let destination = data.join("state");
    std::os::unix::fs::symlink(&sentinel, &destination).unwrap();
    let directory_metadata = directory.metadata().unwrap();
    let ownership = Ownership {
        uid: directory_metadata.uid(),
        gid: directory_metadata.gid(),
        mode: 0o400,
    };
    publish(
        &staging,
        &destination,
        b"owned",
        ownership,
        Publication::Replace,
    )
    .unwrap();
    assert_eq!(std::fs::read(&sentinel).unwrap(), b"intact");
    assert_eq!(std::fs::read(&destination).unwrap(), b"owned");
}
