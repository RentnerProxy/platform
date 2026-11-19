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
    assert!(!super::writers_present(root, &[], is_app).unwrap());
    for field in 0..4 {
        let mut identities = [0; 4];
        identities[field] = 59_999;
        write_status(root, "30", "S", identities);
        assert!(super::writers_present(root, &[], is_app).unwrap());
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
    assert!(super::writers_present(root, &[], is_app).is_err());
    assert!(parse_status(b"State:\tS\nUid:\t0 0 0 0 0\n").is_err());
    assert!(
        inspect_live_entry(&root.join("43"), std::time::Instant::now())
            .unwrap()
            .is_none()
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
        format!("State:\t{state} (fixture)\nThreads:\t1\nUid:\t{real} {effective} {saved} {filesystem}\n"),
    )
    .unwrap();
}

#[test]
fn checks_live_siblings_of_an_exited_leader_and_requires_a_visible_task_list() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path();
    write_status(root, "self", "S", [0; 4]);
    write_status(root, "70", "Z", [0; 4]);
    fs::write(root.join("70/status"), "State: Z\nThreads: 2\n").unwrap();
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

#[test]
fn live_leaders_require_every_worker_identity() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path();
    write_status(root, "self", "S", [0; 4]);
    write_status(root, "80", "S", [0; 4]);
    let census = || super::writers_present(root, &[], is_app);
    assert!(!census().unwrap());

    let status = root.join("80/status");
    fs::write(&status, "State: S\nUid: 0 0 0 0\nThreads: 2\n").unwrap();
    assert!(census().is_err());
    let tasks = root.join("80/task");
    write_status(&tasks, "80", "S", [0; 4]);
    assert!(census().is_err());
    write_status(&tasks, "81", "S", [0, 0, 20_000, 0]);
    assert!(census().unwrap());
    write_status(&tasks, "81", "S", [0; 4]);
    assert!(!census().unwrap());
    for threads in ["0", "invalid"] {
        fs::write(
            &status,
            format!("State: S\nUid: 0 0 0 0\nThreads: {threads}\n"),
        )
        .unwrap();
        assert!(census().is_err());
    }
}

#[test]
fn hidden_group_requires_a_complete_cgroup_thread_census() {
    let fixture = tempfile::tempdir().unwrap();
    let proc = fixture.path();
    let cgroup = proc.join("domain");
    fs::create_dir(&cgroup).unwrap();
    write_status(proc, "40", "Z", [0; 4]);
    let leader = proc.join("40/status");
    let run = || {
        super::hidden_group_has_writer(
            proc,
            &cgroup,
            40,
            std::time::Instant::now() + super::SCAN_BUDGET,
            &is_app,
        )
    };
    fs::write(&leader, "State: Z\nTgid: 40\nThreads: 1\n").unwrap();
    assert!(!run().unwrap());
    fs::write(&leader, "State: Z\nTgid: 40\nThreads: 2\n").unwrap();
    fs::write(proc.join("40/cgroup"), "0::/\n").unwrap();
    fs::write(cgroup.join("cgroup.type"), "domain\n").unwrap();
    fs::write(cgroup.join("cgroup.threads"), "0\n3\n40\n41\n41\n42\n").unwrap();
    write_status(proc, "41", "S", [0; 4]);
    fs::write(proc.join("41/status"), "State: S\nTgid: 40\nUid: 0 0 0 0\n").unwrap();
    write_status(proc, "42", "S", [0; 4]);
    fs::write(
        proc.join("42/status"),
        "State: S\nTgid: 42\nUid: 22000 0 0 0\n",
    )
    .unwrap();
    assert!(!run().unwrap());
    fs::write(
        proc.join("41/status"),
        "State: S\nTgid: 40\nUid: 0 20000 0 0\n",
    )
    .unwrap();
    assert!(run().unwrap());
    fs::write(proc.join("41/status"), "State: S\nTgid: 40\nUid: 0 0 0 0\n").unwrap();
    fs::write(cgroup.join("cgroup.threads"), "40\n").unwrap();
    assert!(run().is_err());
    fs::write(cgroup.join("cgroup.threads"), "40\n41\n").unwrap();
    assert!(!run().unwrap());
    fs::write(cgroup.join("cgroup.type"), "threaded\n").unwrap();
    assert!(run().is_err());
    fs::write(cgroup.join("cgroup.type"), "domain\n").unwrap();
    fs::write(cgroup.join("cgroup.threads"), b"invalid-tid\n").unwrap();
    assert!(run().is_err());
    fs::write(cgroup.join("cgroup.threads"), b"\xff").unwrap();
    assert!(run().is_err());
    fs::write(cgroup.join("cgroup.threads"), "40\n41\n").unwrap();
    assert!(!run().unwrap());
    fs::write(proc.join("40/cgroup"), "0::/other\n").unwrap();
    assert!(run().is_err());
    fs::write(proc.join("40/cgroup"), "0::/\n").unwrap();
    let changed = super::hidden_group_has_writer(
        proc,
        &cgroup,
        40,
        std::time::Instant::now() + super::SCAN_BUDGET,
        &|_| {
            fs::write(&leader, "State: Z\nTgid: 40\nThreads: 3\n").unwrap();
            false
        },
    );
    assert!(changed.is_err());
    fs::write(&leader, "State: S\nTgid: 40\nThreads: 1\nUid: 0 0 0 0\n").unwrap();
    assert!(run().is_err());
}
