use std::{fs, path::Path};

use super::{Consumers, inspect_live_entry, is_app, parse_status, verify_writers_stopped};

#[test]
fn guards_every_kernel_credential_and_respects_the_uid_pool() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path();
    write_status(root, "self", "S", [0, 0, 0, 0]);
    write_status(root, "18", "S", [19_999, 0, 60_000, 0]);
    write_status(root, "21", "Z", [20_000, 20_000, 20_000, 20_000]);
    write_status(&root.join("21/task"), "21", "Z", [20_000; 4]);
    verify_writers_stopped(root, &[], is_app).unwrap();
    for field in 0..4 {
        let mut identities = [0; 4];
        identities[field] = 59_999;
        write_status(root, "30", "S", identities);
        assert!(verify_writers_stopped(root, &[], is_app).is_err());
    }
}

#[test]
fn fails_closed_for_truncated_or_unreadable_identity() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path();
    write_status(root, "self", "S", [0, 0, 0, 0]);
    fs::create_dir(root.join("42")).unwrap();
    assert!(verify_writers_stopped(root, &[], is_app).is_err());
    fs::write(root.join("42/status"), "State:\tS\nUid:\t0 0 0\n").unwrap();
    assert!(verify_writers_stopped(root, &[], is_app).is_err());
    assert!(parse_status(b"State:\tS\nUid:\t0 0 0 0 0\n").is_err());
    assert_eq!(
        inspect_live_entry(&root.join("43"), std::time::Instant::now()).unwrap(),
        None,
    );
}

#[test]
fn protects_web_and_backup_consumers_with_scoped_recovery_exclusions() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path();
    write_status(root, "self", "S", [0; 4]);
    let web = Consumers::Web;
    let backup = Consumers::Backup {
        preserve_web: false,
    };
    let restore = Consumers::Backup { preserve_web: true };
    for field in 0..4 {
        let mut credentials = [0; 4];
        credentials[field] = 10_002;
        write_status(root, "40", "S", credentials);
        assert!(verify_writers_stopped(root, &[], |uid| web.includes(uid)).is_err());
        assert!(verify_writers_stopped(root, &[], |uid| backup.includes(uid)).is_err());
        verify_writers_stopped(root, &[], |uid| restore.includes(uid)).unwrap();
    }
    write_status(root, "41", "S", [10_001; 4]);
    write_status(root, "42", "S", [10_001; 4]);
    assert!(verify_writers_stopped(root, &[41], |uid| restore.includes(uid)).is_err());
    verify_writers_stopped(root, &[41, 42], |uid| restore.includes(uid)).unwrap();
    for uid in [10_003, 20_000, 59_999] {
        write_status(root, "43", "S", [uid; 4]);
        assert!(verify_writers_stopped(root, &[41, 42], |uid| restore.includes(uid)).is_err());
    }
}

fn write_status(root: &Path, pid: &str, state: &str, uids: [u32; 4]) {
    let directory = root.join(pid);
    fs::create_dir_all(&directory).unwrap();
    let [real, effective, saved, filesystem] = uids;
    fs::write(
        directory.join("status"),
        format!("State:\t{state} (fixture)\nUid:\t{real} {effective} {saved} {filesystem}\n"),
    )
    .unwrap();
}

#[test]
fn checks_live_siblings_of_an_exited_leader_and_requires_a_visible_task_list() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path();
    write_status(root, "self", "S", [0; 4]);
    write_status(root, "70", "Z", [0; 4]);
    assert!(verify_writers_stopped(root, &[], is_app).is_err());
    let tasks = root.join("70/task");
    fs::create_dir(&tasks).unwrap();
    assert!(verify_writers_stopped(root, &[], is_app).is_err());
    write_status(&tasks, "70", "Z", [0; 4]);
    write_status(&tasks, "71", "S", [0, 20_001, 0, 0]);
    assert!(verify_writers_stopped(root, &[], is_app).is_err());
    write_status(&tasks, "71", "X", [20_001; 4]);
    verify_writers_stopped(root, &[], is_app).unwrap();
}
