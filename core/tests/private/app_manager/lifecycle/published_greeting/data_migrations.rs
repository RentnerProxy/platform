//! Declared data migrations of signed Greeting releases through the real app manager.
//!
//! Four releases repackage the official Greeting 1.0.1 archive with SQL migrations. 1.1.0
//! creates the app schema, 1.2.0 fails inside its migration, 1.3.0 upgrades the data and
//! 1.4.0 commits a migration before its backend refuses to start. One fresh appliance state
//! installs, updates, refuses a rollback the data no longer supports and recovers through the
//! catalog UI.

use super::distribution::{self, Distribution};
use super::portable_backup::postgres;
use super::repackage::{Repackaged, generation, installation, offer, repackage};
use super::*;
use crate::app_manager::migration::recorded_version;
use rentnerproxy_artifacts::digest;

/// SQL steps by name. Step `n` of a release migrates data version `n` to `n + 1`.
const STEPS: [(&str, &str); 4] = [
    (
        "initialize",
        "CREATE TABLE app.notes (id integer PRIMARY KEY, body text NOT NULL);
INSERT INTO app.notes (id, body) VALUES (1, 'first'), (2, 'second');
CREATE TABLE app.migration_log (step integer NOT NULL);
INSERT INTO app.migration_log (step) VALUES (1);
",
    ),
    (
        // One change, then a statement that violates a constraint in the same transaction.
        "broken",
        "ALTER TABLE app.notes ADD COLUMN revision integer NOT NULL DEFAULT 2;
INSERT INTO app.notes (id) VALUES (3);
",
    ),
    (
        "upgrade",
        "ALTER TABLE app.notes ADD COLUMN revision integer NOT NULL DEFAULT 2;
INSERT INTO app.migration_log (step) VALUES (2);
",
    ),
    (
        // Rerunnable, so only the log shows whether recovery migrated a second time.
        "archive",
        "ALTER TABLE app.notes ADD COLUMN IF NOT EXISTS archived boolean NOT NULL DEFAULT false;
INSERT INTO app.migration_log (step) VALUES (3);
",
    ),
];

/// The repackaged releases in publication order with their declared steps from fresh state.
const RELEASES: [(&str, &[&str]); 4] = [
    ("1.1.0", &["initialize"]),
    ("1.2.0", &["initialize", "broken"]),
    ("1.3.0", &["initialize", "upgrade"]),
    ("1.4.0", &["initialize", "upgrade", "archive"]),
];

fn step_sql(name: &str) -> &'static str {
    STEPS
        .iter()
        .find(|(step, _)| *step == name)
        .map(|(_, sql)| *sql)
        .expect("declared migration step")
}

/// The manifest data block: the release reads and writes only its target version.
fn data(steps: &[&str]) -> Value {
    let target = steps.len();
    json!({
        "targetVersion": target,
        "readVersions": [target],
        "writeVersions": [target],
        "migrations": steps.iter().enumerate().map(|(from, name)| json!({
            "fromVersion": from,
            "toVersion": from + 1,
            "path": format!("migrations/{name}.sql"),
        })).collect::<Vec<_>>(),
    })
}

/// Each release with its data block and the SQL files of its declared steps.
fn repackaged() -> [Repackaged; 4] {
    RELEASES.map(|(version, steps)| Repackaged {
        version,
        fields: json!({"data": data(steps)}),
        files: steps
            .iter()
            .map(|name| {
                (
                    format!("migrations/{name}.sql"),
                    step_sql(name).as_bytes().to_vec(),
                )
            })
            .collect(),
    })
}

async fn app_query(uid: u32, sql: &str) -> String {
    postgres(uid, &format!("SET ROLE rp_app_{uid}; {sql}")).await
}

/// The migrated app data as the app's runtime role sees it, with the recorded data version.
#[derive(Debug, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct AppDatabase {
    recorded_version: Option<u32>,
    columns: String,
    notes: String,
    migration_log: String,
}

impl AppDatabase {
    fn expected(version: u32, columns: &str, notes: &str, migration_log: &str) -> Self {
        Self {
            recorded_version: Some(version),
            columns: columns.into(),
            notes: notes.into(),
            migration_log: migration_log.into(),
        }
    }

    async fn observe(uid: u32) -> Self {
        Self {
            recorded_version: recorded_version(uid).await.unwrap(),
            columns: app_query(
                uid,
                "SELECT string_agg(attname::text, ',' ORDER BY attnum) FROM pg_catalog.pg_attribute \
                 WHERE attrelid = 'app.notes'::regclass AND attnum > 0 AND NOT attisdropped;",
            )
            .await,
            notes: app_query(
                uid,
                "SELECT string_agg(note::text, ';' ORDER BY note.id) FROM app.notes AS note;",
            )
            .await,
            migration_log: app_query(
                uid,
                "SELECT string_agg(step::text, ',' ORDER BY step) FROM app.migration_log;",
            )
            .await,
        }
    }
}

/// Write the app-owned greeting state as the app leaves it: owned by its UID, mode 0600.
fn write_state(path: &Path, uid: u32, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    chown(path, Some(uid), Some(uid)).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[tokio::test]
#[ignore = "requires native Linux, root, the published Greeting fixture and isolated PostgreSQL"]
async fn privileged_published_greeting_data_migrations() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    require_isolated_state();
    distribution::require_loopback_hosts();
    let controller = PathBuf::from(std::env::var_os("RENTNERPROXY_TEST_CONTROLLER").unwrap());
    let fixture_path = PathBuf::from(std::env::var_os("RP_GREETING_FIXTURE").unwrap());
    let report_path = PathBuf::from(std::env::var_os("RP_GREETING_MIGRATIONS_REPORT").unwrap());
    let mut fixture = crate::app_install::tests::published_greeting::prepare(&fixture_path);
    let installer = InstallerFixture::new(&fixture.root);
    let releases = repackage(&mut fixture, installer.work.path(), &repackaged());
    let [initial, broken, upgrade, committed] = &releases;
    let installation_id = format!("app-{}", &digest(APP_ID.as_bytes())[..32]);
    let mut authority = start_authority(&installation_id, None).await;
    let hosts = Distribution::start(installer.work.path(), initial.files.clone(), &releases);
    let mut manager = start_manager(&controller, &installer.config, &installer.token, None).await;

    // 1. A fresh install runs the release's step from empty state and records version 1.
    let listing = wait_catalog_state("ready").await;
    assert!(listing["entries"].as_array().unwrap().iter().any(|entry| {
        entry["appId"] == APP_ID
            && entry["version"] == initial.version
            && entry["archiveSha256"] == initial.archive_sha256
            && entry["availability"] == "available"
    }));
    let (status, body) = send_ui(
        "POST",
        "/v1/catalog/install",
        Some(&json!({
            "appId": APP_ID,
            "version": initial.version,
            "archiveSha256": initial.archive_sha256,
        })),
    )
    .await;
    assert_eq!(status, 202, "{body}");
    let installed_view = wait_install("installed").await;
    let installed = running_installation(&installed_view, &installation_id).clone();
    assert_eq!(installed["version"], initial.version);
    assert_eq!(installed["archiveSha256"], initial.archive_sha256);
    let installed_generation = generation(&installed);
    save_greeting(&installation_id, installed_generation, PERSISTED_GREETING).await;
    let uid = manager_status().await.unwrap()[&installation_id]["uid"]
        .as_u64()
        .unwrap();
    let uid = u32::try_from(uid).unwrap();
    let state_path = PathBuf::from(format!(
        "/var/lib/rentnerproxy/apps/{uid}/data/greeting.json"
    ));
    let state = fs::read(&state_path).unwrap();
    let fresh = AppDatabase::observe(uid).await;
    assert_eq!(
        fresh,
        AppDatabase::expected(1, "id,body", "(1,first);(2,second)", "1")
    );

    // 2. A migration that fails inside its transaction changes no data. The fallback restarts
    // the previous release with its approved grants in a new generation.
    let before = offer(
        &hosts,
        broken,
        &mut manager,
        &controller,
        &installer,
        &installation_id,
    )
    .await;
    post_lifecycle(&lifecycle_request(
        "update",
        &before,
        Some(&before["update"]),
    ))
    .await;
    let failed_view = wait_lifecycle("update", "failed").await;
    let failed_migration = failed_view["lifecycle"].clone();
    assert_eq!(
        failed_migration["error"], "operationFailed",
        "{failed_view}"
    );
    let restarted = running_installation(&failed_view, &installation_id);
    assert_eq!(restarted["version"], initial.version);
    assert_eq!(restarted["archiveSha256"], initial.archive_sha256);
    let restarted_generation = generation(restarted);
    assert_eq!(restarted_generation, generation(&before) + 2);
    let restarted_status = manager_status().await.unwrap()[&installation_id].clone();
    assert_eq!(restarted_status["active"], initial.version);
    assert_eq!(restarted_status["running"], true);
    assert_eq!(restarted_status["recoveryRequired"], false);
    assert_eq!(
        AppDatabase::observe(uid).await,
        fresh,
        "the failed step left a partial change"
    );
    assert_eq!(
        read_greeting(&installation_id, restarted_generation).await,
        PERSISTED_GREETING
    );
    assert_eq!(fs::read(&state_path).unwrap(), state);

    // 3. The next release migrates version 1 to 2 and keeps the rows.
    let before = offer(
        &hosts,
        upgrade,
        &mut manager,
        &controller,
        &installer,
        &installation_id,
    )
    .await;
    post_lifecycle(&lifecycle_request(
        "update",
        &before,
        Some(&before["update"]),
    ))
    .await;
    let updated_view = wait_lifecycle("update", "succeeded").await;
    let updated = running_installation(&updated_view, &installation_id).clone();
    assert_eq!(updated["version"], upgrade.version);
    assert_eq!(updated["archiveSha256"], upgrade.archive_sha256);
    assert_eq!(updated["previous"]["version"], initial.version);
    assert_eq!(updated["previous"]["archiveSha256"], initial.archive_sha256);
    let updated_generation = generation(&updated);
    assert_eq!(updated_generation, generation(&before) + 1);
    let migrated = AppDatabase::observe(uid).await;
    assert_eq!(
        migrated,
        AppDatabase::expected(2, "id,body,revision", "(1,first,2);(2,second,2)", "1,2")
    );
    assert_eq!(
        read_greeting(&installation_id, updated_generation).await,
        PERSISTED_GREETING
    );

    // 4. 1.1.0 cannot open version 2. The manager refuses the rollback before the fence.
    let status_before = manager_status().await.unwrap()[&installation_id].clone();
    post_lifecycle(&lifecycle_request(
        "rollback",
        &updated,
        Some(&updated["previous"]),
    ))
    .await;
    let refused_view = wait_lifecycle("rollback", "failed").await;
    let refused_rollback = refused_view["lifecycle"].clone();
    assert_eq!(
        refused_rollback["error"], "incompatibleData",
        "{refused_view}"
    );
    let unchanged = running_installation(&refused_view, &installation_id);
    assert_eq!(generation(unchanged), updated_generation);
    assert_eq!(unchanged["version"], upgrade.version);
    assert_eq!(unchanged["archiveSha256"], upgrade.archive_sha256);
    assert_eq!(
        manager_status().await.unwrap()[&installation_id],
        status_before
    );
    assert_eq!(AppDatabase::observe(uid).await, migrated);
    assert_eq!(
        read_greeting(&installation_id, updated_generation).await,
        PERSISTED_GREETING
    );
    assert_eq!(fs::read(&state_path).unwrap(), state);

    // 5. The migration to version 3 commits, then the backend exits on invalid state. 1.3.0
    // cannot open version 3, so the installation waits for recovery instead of losing data.
    let before = offer(
        &hosts,
        committed,
        &mut manager,
        &controller,
        &installer,
        &installation_id,
    )
    .await;
    write_state(&state_path, uid, b"{}\n");
    post_lifecycle(&lifecycle_request(
        "update",
        &before,
        Some(&before["update"]),
    ))
    .await;
    let stopped_view = wait_lifecycle("update", "failed").await;
    let failed_start = stopped_view["lifecycle"].clone();
    assert_eq!(failed_start["error"], "operationFailed", "{stopped_view}");
    let stopped = installation(&stopped_view, &installation_id).clone();
    assert_eq!(stopped["state"], "recoveryRequired", "{stopped}");
    assert_eq!(stopped["version"], upgrade.version);
    let stopped_generation = generation(&stopped);
    assert_eq!(stopped_generation, generation(&before) + 1);
    let stopped_status = manager_status().await.unwrap()[&installation_id].clone();
    assert_eq!(stopped_status["running"], false);
    assert_eq!(stopped_status["recoveryRequired"], true);
    assert_eq!(stopped_status["active"], upgrade.version);
    assert_eq!(stopped_status["candidate"], committed.version);
    let committed_data = AppDatabase::observe(uid).await;
    assert_eq!(
        committed_data,
        AppDatabase::expected(
            3,
            "id,body,revision,archived",
            "(1,first,2,f);(2,second,2,f)",
            "1,2,3"
        )
    );

    // Recovery reopens the active release, finds it incompatible and finishes the staged
    // activation whose migration committed, without migrating again.
    write_state(&state_path, uid, &state);
    post_lifecycle(&lifecycle_request("recover", &stopped, None)).await;
    let recovered_view = wait_lifecycle("recover", "succeeded").await;
    let recovered = running_installation(&recovered_view, &installation_id);
    assert_eq!(recovered["version"], committed.version);
    assert_eq!(recovered["archiveSha256"], committed.archive_sha256);
    assert_eq!(recovered["previous"]["version"], upgrade.version);
    let recovered_generation = generation(recovered);
    assert_eq!(recovered_generation, stopped_generation + 1);
    let recovered_status = manager_status().await.unwrap()[&installation_id].clone();
    assert_eq!(recovered_status["active"], committed.version);
    assert_eq!(recovered_status["candidate"], Value::Null);
    assert_eq!(recovered_status["running"], true);
    assert_eq!(recovered_status["recoveryRequired"], false);
    assert_eq!(
        AppDatabase::observe(uid).await,
        committed_data,
        "recovery ran the migration again"
    );
    assert_eq!(
        read_greeting(&installation_id, recovered_generation).await,
        PERSISTED_GREETING
    );
    halt(&mut manager).await;
    authority.kill().await.unwrap();
    drop(hosts);

    let architecture = if cfg!(target_arch = "x86_64") {
        "linux-amd64"
    } else {
        "linux-arm64"
    };
    let base = &fixture.snapshots[1];
    let evidence = json!({
        "schemaVersion": 1,
        "architecture": architecture,
        "appId": APP_ID,
        "installationId": installation_id,
        "repackagedFrom": {
            "version": base.version,
            "officialCommit": base.official_commit,
            "archiveSha256": base.archive_sha256,
        },
        "releases": releases.iter().zip(RELEASES).map(|(release, (_, steps))| json!({
            "version": release.version,
            "catalogRevision": release.catalog_revision,
            "archiveSha256": release.archive_sha256,
            "archiveSizeBytes": release.archive_size_bytes,
            "manifestSha256": release.manifest_sha256,
            "data": data(steps),
        })).collect::<Vec<_>>(),
        "install": {
            "version": initial.version,
            "generation": installed_generation,
            "database": fresh,
        },
        "failedMigration": {
            "operation": failed_migration,
            "restarted": {"version": initial.version, "generation": restarted_generation},
            "databaseUnchanged": true,
            "greetingVerified": true,
        },
        "migratedUpdate": {
            "operation": updated_view["lifecycle"],
            "generation": updated_generation,
            "database": migrated,
        },
        "incompatibleRollback": {
            "operation": refused_rollback,
            "generationUnchanged": updated_generation,
            "databaseUnchanged": true,
            "greetingVerified": true,
        },
        "committedMigrationRecovery": {
            "failedStart": failed_start,
            "recoveryRequiredGeneration": stopped_generation,
            "database": committed_data,
            "recovery": recovered_view["lifecycle"],
            "recovered": {"version": committed.version, "generation": recovered_generation},
            "migratedAgain": false,
            "greetingVerified": true,
        },
    });
    fs::create_dir_all(report_path.parent().unwrap()).unwrap();
    fs::write(&report_path, serde_json::to_vec_pretty(&evidence).unwrap()).unwrap();
}
