use super::*;

#[tokio::test]
#[ignore = "requires the ephemeral PostgreSQL cluster from app-provision.sh"]
async fn privileged_postgres_uid_fencing() {
    use std::process::Stdio;
    use tokio::process::Command as Process;
    fn psql(user: &str, database: &str) -> Process {
        let mut command = Process::new("/usr/lib/postgresql/18/bin/psql");
        command
            .env_clear()
            .args([
                "--no-psqlrc",
                "--no-password",
                "--no-align",
                "--tuples-only",
                "--set=ON_ERROR_STOP=1",
                "--host=/var/run/postgresql",
                "--username",
                user,
                "--dbname",
                database,
            ])
            .kill_on_drop(true);
        command
    }
    async fn query(sql: &str) -> String {
        let output = psql("postgres", "postgres")
            .args(["--command", sql])
            .output()
            .await
            .unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }
    fn session(role: &str, database: &str) -> tokio::process::Child {
        psql(role, database)
            .env("PGAPPNAME", "fixture-uid-fence")
            .args(["--command", "SELECT pg_sleep(20)"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    }
    // These are backend PIDs of our own sessions in the isolated fixture cluster.
    struct PausedBackends(Vec<i32>);
    impl Drop for PausedBackends {
        fn drop(&mut self) {
            for &pid in &self.0 {
                unsafe {
                    libc::kill(pid, libc::SIGCONT);
                }
            }
        }
    }
    assert_eq!(
        query("SHOW data_directory").await,
        "/tmp/app-provision-postgres"
    );
    let temp = tempfile::tempdir_in("/var/lib/rentnerproxy").unwrap();
    let manager = Manager {
        ui: ui::Registry::default(),
        listener: None,
        config: Some(temp.path().join("offline")),
        journal: Journal::open(&temp.path().join("manager")).unwrap(),
        gateway: Gateway::fixture(temp.path().join("absent.sock"), 0),
        running: BTreeMap::new(),
        fence_cursor: String::new(),
        drains: JoinSet::new(),
        draining: HashMap::new(),
    };
    let first = manager.allocate("fixture.app".into()).await.unwrap().uid;
    let mut unrelated = Process::new("/bin/sleep")
        .arg("15")
        .uid(first)
        .gid(first)
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    assert!(uid_in_use(first).unwrap());
    assert!(manager.allocate("fixture.app".into()).await.unwrap().uid > first);
    unrelated.kill().await.unwrap();
    assert!(!runtime::database_uid_vacant(59182).await.unwrap());
    assert!(!runtime::database_uid_vacant(59183).await.unwrap());
    assert!(runtime::database_uid_vacant(59184).await.unwrap());
    assert!(runtime::database_uid_vacant(60000).await.is_err());
    // Simulate a migration login left open and exhaust the app's four connection slots.
    query("ALTER ROLE rp_migrate_59182 LOGIN").await;
    let mut sessions: Vec<_> = (0..4)
        .map(|_| session("rp_app_59182", "rp_app_59182"))
        .collect();
    sessions.push(session("rp_migrate_59182", "postgres"));
    let mut other = session("rp_app_59183", "rp_app_59183");
    let pids = timeout(Duration::from_secs(5), async {
        loop {
            let pids: Vec<i32> = query("SELECT pid FROM pg_stat_activity WHERE usename IN ('rp_app_59182','rp_migrate_59182') AND application_name='fixture-uid-fence' AND wait_event='PgSleep'")
                .await.lines().map(|pid| pid.parse().unwrap()).collect();
            if pids.len() == sessions.len() && query("SELECT count(*) FROM pg_stat_activity WHERE usename='rp_app_59183' AND application_name='fixture-uid-fence' AND wait_event='PgSleep'").await == "1" {
                return pids;
            }
            sleep(Duration::from_millis(20)).await;
        }
    }).await.unwrap();
    let mut paused = PausedBackends(Vec::new());
    for pid in pids {
        assert_eq!(unsafe { libc::kill(pid, libc::SIGSTOP) }, 0);
        paused.0.push(pid);
    }
    let mut fence = tokio::spawn(runtime::fence_database(59182));
    // No target can exit yet. All five must receive SIGTERM before waiting for any one.
    timeout(Duration::from_secs(3), async {
        while !paused.0.iter().all(|pid| {
            std::fs::read_to_string(format!("/proc/{pid}/status"))
                .unwrap()
                .lines()
                .filter_map(|line| {
                    line.strip_prefix("SigPnd:")
                        .or_else(|| line.strip_prefix("ShdPnd:"))
                })
                .any(|mask| {
                    u64::from_str_radix(mask.trim(), 16).unwrap() & (1 << (libc::SIGTERM - 1)) != 0
                })
        }) {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(query("SELECT count(*) FROM pg_roles WHERE rolname IN ('rp_app_59182','rp_migrate_59182') AND NOT rolcanlogin").await, "2");
    assert!(
        timeout(Duration::from_millis(150), &mut fence)
            .await
            .is_err()
    );
    drop(paused);
    timeout(Duration::from_secs(3), &mut fence)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(query("SELECT count(*) FROM pg_stat_activity WHERE usename IN ('rp_app_59182','rp_migrate_59182')").await, "0");
    for mut child in sessions {
        assert!(
            !timeout(Duration::from_secs(3), child.wait())
                .await
                .unwrap()
                .unwrap()
                .success()
        );
    }
    assert_eq!(query("SELECT count(*) FROM pg_stat_activity WHERE usename='rp_app_59183' AND application_name='fixture-uid-fence'").await, "1");
    other.kill().await.unwrap();
    runtime::purge_database(59182).await.unwrap();
    assert!(runtime::database_uid_vacant(59182).await.unwrap());
    assert_eq!(
        query("SELECT rolcanlogin FROM pg_roles WHERE rolname='rp_app_59183'").await,
        "t"
    );
    assert!(!runtime::database_uid_vacant(59183).await.unwrap());
}
#[path = "app_manager/lifecycle.rs"]
mod lifecycle;
#[path = "app_manager/retirement.rs"]
mod retirement;
#[tokio::test]
#[ignore = "requires the isolated Linux lifecycle fixture and a dedicated writable appliance tmpfs"]
async fn privileged_signed_lifecycle() {
    lifecycle::exercise().await;
}

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

fn release(version: &str) -> Release {
    Release {
        version: version.into(),
        archive_sha256: "a".repeat(64),
        manifest_sha256: "b".repeat(64),
        catalog_revision: 1,
    }
}

#[test]
fn data_changes_preserve_every_possible_written_version_or_require_recovery() {
    let manifest =
        json!({"targetVersion":2.0,"readVersions":[1,2.0,3],"writeVersions":[2,3],"migrations":[]});
    let source = read_data(&manifest).unwrap();
    let next = release("2");
    let keep = Some(DataChange::Keep);
    assert_eq!(Slot::default().plan(&next, None, None, true), keep);
    assert_eq!(Slot::default().plan(&next, Some(&source), None, true), keep);
    let slot = Slot {
        active: Some(release("1")),
        written: Some(source.clone()),
        ..Default::default()
    };
    let mut target = source.clone();
    assert_eq!(slot.plan(&next, Some(&target), None, true), keep);
    target.write_versions.retain(|v| *v != 3);
    assert_eq!(slot.plan(&next, Some(&target), None, true), None);
    target = source.clone();
    target.read_versions.retain(|v| *v != 3);
    assert_eq!(slot.plan(&next, Some(&target), None, true), None);
    target = source.clone();
    target.target_version = 3;
    assert_eq!(slot.plan(&next, Some(&target), None, true), None);
    assert_eq!(slot.plan(&next, None, None, true), None);
}

#[test]
fn declared_sql_migrations_advance_data_that_restarts_only_open() {
    let data = |target: u32, read: &[u32], write: &[u32], steps: Value| Data {
        target_version: target,
        read_versions: read.to_vec(),
        write_versions: write.to_vec(),
        migrations: steps.as_array().unwrap().clone(),
    };
    let initialize = json!({"fromVersion":0,"toVersion":1,"path":"migrations/initialize.sql"});
    let upgrade = json!({"fromVersion":1,"toVersion":2,"path":"migrations/v2/upgrade.sql"});
    let v1 = data(1, &[1], &[1], json!([initialize.clone()]));
    let v2 = data(2, &[1, 2], &[2], json!([initialize, upgrade]));
    let migrate = |from, to, steps: &[&str]| {
        Some(DataChange::Migrate(journal::Migration {
            from,
            to,
            steps: steps
                .iter()
                .map(|step| format!("migrations/{step}"))
                .collect(),
        }))
    };

    // A fresh installation runs the whole chain from version zero.
    assert_eq!(
        Slot::default().plan(&release("1"), Some(&v1), None, true),
        migrate(0, 1, &["initialize.sql"])
    );
    assert_eq!(
        Slot::default().plan(&release("2"), Some(&v2), None, true),
        migrate(0, 2, &["initialize.sql", "v2/upgrade.sql"])
    );

    // An update continues from the recorded version, or from the older declaration.
    let installed = Slot {
        active: Some(release("1")),
        written: Some(v1.clone()),
        database_provisioned: true,
        ..Default::default()
    };
    for recorded in [Some(1), None] {
        assert_eq!(
            installed.plan(&release("2"), Some(&v2), recorded, true),
            migrate(1, 2, &["v2/upgrade.sql"])
        );
    }

    // Migrated data opens only in releases that read and write its exact version.
    assert_eq!(
        installed.plan(&release("2"), Some(&v2), Some(2), true),
        Some(DataChange::Keep)
    );
    assert_eq!(
        installed.plan(&release("1"), Some(&v1), Some(2), true),
        None
    );
    let mut tolerant = v1.clone();
    tolerant.read_versions.push(2);
    tolerant.write_versions.push(2);
    assert_eq!(
        installed.plan(&release("1"), Some(&tolerant), Some(2), true),
        Some(DataChange::Keep)
    );
    assert_eq!(installed.plan(&release("3"), None, Some(2), true), None);

    // Restarts, rollbacks and recovery never migrate. They open data the release can already
    // read and write, also below its target when it declares that version.
    assert_eq!(
        installed.plan(&release("2"), Some(&v2), Some(1), false),
        None
    );
    assert_eq!(installed.plan(&release("2"), Some(&v2), None, false), None);
    assert_eq!(
        Slot::default().plan(&release("1"), Some(&v1), None, false),
        None
    );
    let mut forward = v2.clone();
    forward.write_versions.push(1);
    for may_migrate in [false, true] {
        let expected = if may_migrate {
            migrate(1, 2, &["v2/upgrade.sql"])
        } else {
            Some(DataChange::Keep)
        };
        assert_eq!(
            installed.plan(&release("2"), Some(&forward), Some(1), may_migrate),
            expected
        );
    }
    forward.migrations.remove(1);
    assert_eq!(
        installed.plan(&release("2"), Some(&forward), Some(1), true),
        Some(DataChange::Keep)
    );

    // Only the activation that started a migration may later be finished by recovery.
    let mut migrating = installed.clone();
    migrating.migrating = Some((&release("2")).into());
    migrating.commit_release(release("2"));
    assert_eq!(migrating.migrating, None);

    // Only SQL steps on a complete forward chain inside migrations/ can run.
    let mut gap = v2.clone();
    gap.migrations.remove(1);
    assert_eq!(
        installed.plan(&release("2"), Some(&gap), Some(1), true),
        None
    );
    for path in [
        "migrations/v2/upgrade.json",
        "migrations/../upgrade.sql",
        "migrations/.upgrade.sql",
        "migrations/up..grade.sql",
        "migrations//upgrade.sql",
        "migrations/upgrade.sql/",
        "migrations/up grade.sql",
        "other/upgrade.sql",
        "/migrations/upgrade.sql",
    ] {
        let mut unsafe_step = v2.clone();
        unsafe_step.migrations[1]["path"] = path.into();
        assert_eq!(
            installed.plan(&release("2"), Some(&unsafe_step), Some(1), true),
            None,
            "{path}"
        );
    }

    // Data cannot appear under an existing installation without a declared migration.
    let dataless = Slot {
        active: Some(release("0")),
        ..Default::default()
    };
    let mut undeclared = v1.clone();
    undeclared.migrations.clear();
    assert_eq!(
        dataless.plan(&release("1"), Some(&undeclared), None, true),
        None
    );
    assert_eq!(
        dataless.plan(&release("1"), Some(&v1), None, true),
        migrate(0, 1, &["initialize.sql"])
    );
}

/// A release whose archive and manifest digests derive from `digest`.
fn signed(version: &str, digest: char) -> Release {
    Release {
        version: version.into(),
        archive_sha256: digest.to_string().repeat(64),
        manifest_sha256: digest.to_ascii_uppercase().to_string().repeat(64),
        catalog_revision: 1,
    }
}

fn audit(installation_id: &str) -> Grant {
    serde_json::from_value(json!({
        "capability": {"id": "app.audit.record", "scope": "installation"},
        "resourceId": installation_id,
        "allowService": true,
    }))
    .unwrap()
}

fn host_grant(host: &str) -> Grant {
    serde_json::from_value(json!({
        "capability": {"id": "proxy.hosts.read.v1", "scope": "proxyHosts"},
        "resourceId": host,
        "allowService": true,
        "permissionKey": "view",
    }))
    .unwrap()
}

#[test]
fn approvals_bind_to_exact_releases_and_follow_the_releases_a_slot_references() {
    // A journal entry written before approvals were recorded parses without any.
    let legacy = Slot {
        app_id: "fixture.app".into(),
        uid: 20_000,
        generation: 2,
        active: Some(signed("1.0.0", 'a')),
        ..Default::default()
    };
    let stored = serde_json::to_value(&legacy).unwrap();
    assert!(stored.get("approvals").is_none(), "{stored}");
    let mut slot: Slot = serde_json::from_value(stored).unwrap();
    assert!(slot.approvals.is_empty());
    let active = signed("1.0.0", 'a');
    assert!(slot.approval_for(&active).unwrap().is_none());

    // An approval binds the archive and the manifest digest.
    slot.approve(&active, vec![audit("fixture"), host_grant("h1")]);
    assert_eq!(slot.approval_for(&active).unwrap().unwrap().len(), 2);
    let stored = serde_json::to_value(&slot).unwrap();
    assert_eq!(
        stored["approvals"]["a".repeat(64)]["manifestSha256"],
        "A".repeat(64)
    );
    let mut altered = active.clone();
    altered.manifest_sha256 = "f".repeat(64);
    let error = slot.approval_for(&altered).unwrap_err();
    assert!(error.get_ref().unwrap().is::<journal::ApprovalMismatch>());
    let reparsed: Slot = serde_json::from_value(stored).unwrap();
    assert_eq!(reparsed.approvals, slot.approvals);

    // Revoking removes a grant from every stored approval.
    let (previous, candidate, unrelated) = (
        signed("0.9.0", 'b'),
        signed("1.1.0", 'c'),
        signed("0.1.0", 'd'),
    );
    slot.previous = Some(previous.clone());
    slot.candidate = Some(candidate.clone());
    for release in [&previous, &candidate, &unrelated] {
        slot.approve(
            release,
            vec![audit("fixture"), host_grant("h1"), host_grant("h2")],
        );
    }
    slot.revoke(|grant| grant == &host_grant("h1"));
    for release in [&active, &previous, &candidate, &unrelated] {
        let grants = &slot.approvals[&release.archive_sha256].grants;
        assert!(!grants.contains(&host_grant("h1")));
        assert!(grants.contains(&audit("fixture")));
    }

    // Only the releases the slot can still start or reinstall keep an approval.
    slot.prune_approvals();
    let kept = |slot: &Slot| {
        slot.approvals
            .keys()
            .map(|key| &key[..1])
            .collect::<String>()
    };
    assert_eq!(kept(&slot), "abc");
    // A committed candidate retires the previous release and its approval.
    slot.commit_release(candidate.clone());
    slot.prune_approvals();
    assert_eq!(kept(&slot), "ac");
    // Discarding the retained release drops its approval.
    slot.previous = None;
    slot.prune_approvals();
    assert_eq!(kept(&slot), "c");
    // A removal keeps the approval of the removed release for a reinstall. A purge drops it.
    slot.removed_release = slot.active.take().as_ref().map(Into::into);
    slot.prune_approvals();
    assert_eq!(kept(&slot), "c");
    slot.removed_release = None;
    slot.prune_approvals();
    assert!(slot.approvals.is_empty());
}

#[test]
fn journal_saves_prune_approvals_and_refuse_overflow_without_poisoning() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let temp = tempfile::tempdir_in("/root").unwrap();
    let mut journal = Journal::open(&temp.path().join("manager")).unwrap();
    let active = signed("1.0.0", 'a');
    let mut slot = Slot {
        app_id: "fixture.app".into(),
        uid: 20_001,
        generation: 1,
        active: Some(active.clone()),
        ..Default::default()
    };
    slot.approve(&active, vec![audit("fixture")]);
    slot.approve(&signed("0.1.0", 'd'), vec![audit("fixture")]);
    journal.save("fixture", slot.clone()).unwrap();
    let saved = journal.slot("fixture").unwrap();
    assert_eq!(saved.approvals.len(), 1);
    assert_eq!(
        saved.approval_for(&active).unwrap().unwrap(),
        [audit("fixture")]
    );
    // A journal that would exceed its capacity is refused, and the previous state stays usable.
    let hosts = (0..40_000)
        .map(|index| host_grant(&format!("host-{index}")))
        .collect();
    slot.approve(&active, hosts);
    let error = journal.save("fixture", slot).unwrap_err();
    assert_eq!(error.to_string(), "Manager journal capacity exceeded");
    journal.writable().unwrap();
    assert_eq!(
        journal
            .slot("fixture")
            .unwrap()
            .approval_for(&active)
            .unwrap()
            .unwrap(),
        [audit("fixture")]
    );
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
    // A parallel fixture between fork and exec can temporarily retain our CLOEXEC
    // descriptors. Exercise immediate flock release in an otherwise idle process.
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "app_manager::tests::journal_reopen_fixture",
        ])
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
#[ignore = "private subprocess for the journal reopen test"]
fn journal_reopen_fixture() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
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
    drop(reopened.writer(20000).unwrap());
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
        ui: ui::Registry::default(),
        listener: None,
        config: Some(temp.path().join("offline")),
        journal,
        gateway: Gateway::fixture(temp.path().join("absent.sock"), 0),
        running: BTreeMap::new(),
        fence_cursor: String::new(),
        drains: JoinSet::new(),
        draining: HashMap::new(),
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
