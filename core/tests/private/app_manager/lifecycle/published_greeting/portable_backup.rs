use super::*;
use crate::app_install::tests::published_greeting::PublishedSnapshot;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::{
    fs::OpenOptions,
    io::{Seek, SeekFrom},
    os::unix::fs::OpenOptionsExt,
    process::Stdio,
};

const BUNDLE: &str = "greeting-app-state.bin";
const ROOT: &str = "test-root.json";
const EXPECTED: &str = "expected.json";
const EARLIER_CHECKPOINT: &str = "earlier-checkpoint.json";
const SENTINEL: &str = "original Greeting app database";

async fn postgres(uid: u32, sql: &str) -> String {
    assert!((20_000..=59_999).contains(&uid));
    let output = Process::new("gosu")
        .args([
            "postgres",
            "/usr/lib/postgresql/18/bin/psql",
            "--no-psqlrc",
            "--no-password",
            "--host=/var/run/postgresql",
            "--username=postgres",
            "--quiet",
            "--tuples-only",
            "--no-align",
            "--set=ON_ERROR_STOP=1",
        ])
        .arg(format!("--dbname=rp_app_{uid}"))
        .args(["--command", sql])
        .kill_on_drop(true)
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "isolated app database check failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().into()
}

fn require_offline_network() {
    let interfaces: Vec<_> = fs::read_dir("/sys/class/net")
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert!(
        interfaces.len() == 1 && interfaces[0] == "lo",
        "recovery fixture needs --network none"
    );
}

fn backup_command(controller: &Path, config: &Path, action: &str) -> Process {
    let mut command = Process::new(controller);
    command
        .args(["--app-backup", action])
        .env("RENTNERPROXY_APP_INSTALLER_CONFIG", config)
        .kill_on_drop(true);
    command
}

pub(super) async fn capture(
    controller: &Path,
    fixture: &InstallerFixture,
    manager: &mut Child,
    releases: &[PublishedSnapshot; 2],
    uid: u32,
    directory: &Path,
) {
    require_offline_network();
    halt(manager).await;
    let installation_directory = Path::new("/var/lib/rentnerproxy/apps").join(uid.to_string());
    fs::set_permissions(
        installation_directory.join("database-password"),
        fs::Permissions::from_mode(0o400),
    )
    .unwrap();
    postgres(
        uid,
        &format!(
            "SET ROLE rp_migrate_{uid}; \
             CREATE TABLE app.recovery_sentinel (id integer PRIMARY KEY, note text NOT NULL); \
             INSERT INTO app.recovery_sentinel VALUES (1, '{SENTINEL}'); \
             CREATE TEXT SEARCH CONFIGURATION app.recovery_english (COPY = pg_catalog.english);"
        ),
    )
    .await;
    let bundle = directory.join(BUNDLE);
    let output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&bundle)
        .unwrap();
    assert!(
        backup_command(controller, &fixture.config, "capture-portable")
            .stdout(Stdio::from(output))
            .status()
            .await
            .unwrap()
            .success(),
        "capture the installed application with the native backup entry point"
    );
    let mut magic = [0; 8];
    File::open(bundle).unwrap().read_exact(&mut magic).unwrap();
    assert_eq!(&magic, b"RPAPPB2\0");

    // Supply the test's public pin as an independent installer input on the target.
    fs::copy(&fixture.root, directory.join(ROOT)).unwrap();
    let earlier_files: std::collections::BTreeMap<_, _> = releases[0]
        .files
        .iter()
        .map(|(path, bytes)| (path, STANDARD.encode(bytes)))
        .collect();
    fs::write(
        directory.join(EARLIER_CHECKPOINT),
        serde_json::to_vec(&json!({
            "acceptedAt": time::OffsetDateTime::now_utc().unix_timestamp(),
            "pinSha256": marketplace_artifacts::digest(&fs::read(&fixture.root).unwrap()),
            "files": earlier_files,
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        directory.join(EXPECTED),
        serde_json::to_vec(&json!({
            "uid": uid,
            "releases": releases.iter().map(|release| json!({
                "version": release.version,
                "officialCommit": release.official_commit,
                "archiveSha256": release.archive_sha256,
            })).collect::<Vec<_>>(),
        }))
        .unwrap(),
    )
    .unwrap();
}

async fn backup_status(controller: &Path, config: &Path, action: &str, path: &Path) -> bool {
    backup_command(controller, config, action)
        .arg(path)
        .status()
        .await
        .unwrap()
        .success()
}

fn corrupt_copy(bundle: &Path, corrupted: &Path) {
    fs::copy(bundle, corrupted).unwrap();
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(corrupted)
        .unwrap();
    let last = file.seek(SeekFrom::End(-1)).unwrap();
    let mut byte = [0];
    file.read_exact(&mut byte).unwrap();
    byte[0] ^= 1;
    file.seek(SeekFrom::Start(last)).unwrap();
    file.write_all(&byte).unwrap();
}

async fn assert_database(uid: u32) {
    assert_eq!(
        postgres(
            uid,
            &format!("SET ROLE rp_app_{uid}; SELECT note FROM app.recovery_sentinel WHERE id = 1;")
        )
        .await,
        SENTINEL
    );
    assert_eq!(
        postgres(
            uid,
            &format!(
                "SET ROLE rp_app_{uid}; SELECT to_tsvector('app.recovery_english', 'running');"
            )
        )
        .await,
        "'run':1"
    );
}

#[tokio::test]
#[ignore = "requires a separate native Linux container with fresh state and no network"]
async fn privileged_restore_published_greeting() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    require_offline_network();
    require_isolated_state();
    let controller = PathBuf::from(std::env::var_os("RENTNERPROXY_TEST_CONTROLLER").unwrap());
    let directory = PathBuf::from(std::env::var_os("RP_GREETING_RESTORE_DIRECTORY").unwrap());
    let report = PathBuf::from(std::env::var_os("RP_GREETING_RECOVERY_REPORT").unwrap());
    let expected: Value =
        serde_json::from_slice(&fs::read(directory.join(EXPECTED)).unwrap()).unwrap();
    let uid = u32::try_from(expected["uid"].as_u64().unwrap()).unwrap();
    let first = &expected["releases"][0];
    let second = &expected["releases"][1];
    assert_eq!(first["version"], "1.0.0");
    assert_eq!(second["version"], "1.0.1");
    let installer = InstallerFixture::new(&fs::read(directory.join(ROOT)).unwrap());
    let config = &installer.config;
    let bundle = directory.join(BUNDLE);

    let corrupted = installer.work.path().join("corrupted.bin");
    corrupt_copy(&bundle, &corrupted);
    assert!(!backup_status(&controller, config, "verify-portable", &corrupted).await);
    fs::remove_file(corrupted).unwrap();
    assert!(backup_status(&controller, config, "verify-portable", &bundle).await);
    assert!(!Path::new("/var/lib/rentnerproxy/apps").exists());
    assert!(!Path::new("/var/lib/rentnerproxy/app-manager/journal.json").exists());
    let checkpoint = installer.store.join("catalog-checkpoint.json");
    let earlier_checkpoint = fs::read(directory.join(EARLIER_CHECKPOINT)).unwrap();
    fs::write(&checkpoint, &earlier_checkpoint).unwrap();
    fs::set_permissions(&checkpoint, fs::Permissions::from_mode(0o600)).unwrap();

    // Interrupt the database replay after file storage and the recovery marker
    // exist. The control socket stays available to fence the temporary login.
    let app_socket = Path::new("/run/rentnerproxy/app-db");
    let socket_permissions = fs::metadata(app_socket).unwrap().permissions();
    fs::set_permissions(app_socket, fs::Permissions::from_mode(0o700)).unwrap();
    let interrupted = backup_status(&controller, config, "restore-portable", &bundle).await;
    fs::set_permissions(app_socket, socket_permissions.clone()).unwrap();
    assert!(!interrupted);
    assert_eq!(fs::read(&checkpoint).unwrap(), earlier_checkpoint);
    let app_root = Path::new("/var/lib/rentnerproxy/apps").join(uid.to_string());
    let staged_credential = app_root.join(format!(
        "{}fixture",
        crate::protected_files::PRIVATE_STAGING_PREFIX
    ));
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&staged_credential)
        .unwrap();
    assert!(!Path::new("/var/lib/rentnerproxy/app-manager/journal.json").exists());

    assert!(backup_status(&controller, config, "restore-portable", &bundle).await);
    assert!(!staged_credential.exists());
    assert_ne!(fs::read(&checkpoint).unwrap(), earlier_checkpoint);
    assert_database(uid).await;
    // Repeat with the same input before starting the manager, including the
    // completion marker path used if the maintenance caller lost its response.
    postgres(
        uid,
        &format!(
            "SET ROLE rp_app_{uid}; INSERT INTO app.recovery_sentinel VALUES (2, 'target retry witness');"
        ),
    )
    .await;
    assert!(backup_status(&controller, config, "restore-portable", &bundle).await);
    assert_database(uid).await;
    assert_eq!(
        postgres(
            uid,
            &format!("SET ROLE rp_app_{uid}; SELECT note FROM app.recovery_sentinel WHERE id = 2;")
        )
        .await,
        "target retry witness",
        "a completed recovery must preserve subsequent writes on retry"
    );
    let verified = backup_command(&controller, config, "verify-portable")
        .arg(&bundle)
        .output()
        .await
        .unwrap();
    assert!(verified.status.success());
    assert_eq!(verified.stdout, b"restored\n");

    let installation_id = format!(
        "app-{}",
        &marketplace_artifacts::digest(APP_ID.as_bytes())[..32]
    );
    let mut authority = start_authority(&installation_id).await;
    let mut manager = start_manager(
        &controller,
        config,
        &installer.token,
        Some(&installation_id),
    )
    .await;
    let listing = wait_catalog_state("stale").await;
    let restored = running_installation(&listing, &installation_id);
    assert_eq!(restored["version"], second["version"]);
    assert_eq!(restored["archiveSha256"], second["archiveSha256"]);
    assert_eq!(restored["previous"]["version"], first["version"]);
    assert_eq!(
        restored["previous"]["archiveSha256"],
        first["archiveSha256"]
    );
    let restored_generation = restored["generation"].as_u64().unwrap();
    assert_eq!(
        read_greeting(&installation_id, restored_generation).await,
        PERSISTED_GREETING
    );
    assert_database(uid).await;

    post_lifecycle(&lifecycle_request(
        "rollback",
        restored,
        Some(&restored["previous"]),
    ))
    .await;
    let rollback = wait_lifecycle("rollback", "succeeded").await;
    let rolled_back = running_installation(&rollback, &installation_id);
    assert_eq!(rolled_back["version"], first["version"]);
    assert_eq!(rolled_back["archiveSha256"], first["archiveSha256"]);
    let rolled_back_generation = rolled_back["generation"].as_u64().unwrap();
    assert_eq!(rolled_back_generation, restored_generation + 1);
    assert_eq!(
        read_greeting(&installation_id, rolled_back_generation).await,
        PERSISTED_GREETING
    );
    assert_database(uid).await;
    halt(&mut manager).await;

    manager = start_manager(
        &controller,
        config,
        &installer.token,
        Some(&installation_id),
    )
    .await;
    let after_restart = manager_status().await.unwrap()[&installation_id].clone();
    assert_eq!(after_restart["active"], first["version"]);
    assert_eq!(after_restart["generation"], rolled_back_generation + 1);
    assert_eq!(
        read_greeting(&installation_id, rolled_back_generation + 1).await,
        PERSISTED_GREETING
    );
    assert_database(uid).await;
    halt(&mut manager).await;

    // Restoring the backup over the app that has run since replaces it with the
    // captured release, files and database. Untracked storage blocks it first.
    // Like every offline restore, it starts without the app's runtime sockets.
    let runtime = Path::new("/run/rentnerproxy/apps").join(uid.to_string());
    if runtime.exists() {
        fs::remove_dir_all(runtime).unwrap();
    }
    postgres(
        uid,
        &format!("SET ROLE rp_app_{uid}; INSERT INTO app.recovery_sentinel VALUES (3, 'replaced');"),
    )
    .await;
    let untracked = Path::new("/var/lib/rentnerproxy/apps/.untracked");
    fs::create_dir(untracked).unwrap();
    assert!(!backup_status(&controller, config, "verify-portable", &bundle).await);
    assert!(!backup_status(&controller, config, "restore-portable", &bundle).await);
    fs::remove_dir(untracked).unwrap();
    assert!(app_root.join("data").is_dir());
    let marker: Value = serde_json::from_slice(
        &fs::read("/var/lib/rentnerproxy/app-manager/portable-restore.json").unwrap(),
    )
    .unwrap();
    assert_eq!(marker["complete"], true, "a rejected replacement changes nothing");
    assert!(marker.get("retiring").is_none());

    // A session the retirement does not own interrupts it after the marker
    // records it. The installed app remains until the same backup resumes.
    let mut session = Process::new("gosu")
        .args([
            "postgres",
            "/usr/lib/postgresql/18/bin/psql",
            "--no-psqlrc",
            "--no-password",
            "--host=/var/run/postgresql",
            "--username=postgres",
            "--quiet",
        ])
        .arg(format!("--dbname=rp_app_{uid}"))
        .args(["--command", "SELECT pg_sleep(600);"])
        .stdout(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let sessions = "SELECT count(*) FROM pg_stat_activity \
                    WHERE datname = current_database() AND pid <> pg_backend_pid();";
    for attempt in 0.. {
        if postgres(uid, sessions).await == "1" {
            break;
        }
        assert!(attempt < 200, "the foreign app database session did not start");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(!backup_status(&controller, config, "restore-portable", &bundle).await);
    session.kill().await.unwrap();
    let marker: Value = serde_json::from_slice(
        &fs::read("/var/lib/rentnerproxy/app-manager/portable-restore.json").unwrap(),
    )
    .unwrap();
    assert_eq!(marker["retiring"], true);
    assert_eq!(marker["complete"], false);
    let journal: Value = serde_json::from_slice(
        &fs::read("/var/lib/rentnerproxy/app-manager/journal.json").unwrap(),
    )
    .unwrap();
    assert!(journal["installations"].get(&installation_id).is_some());
    assert!(app_root.join("data").is_dir());
    for attempt in 0.. {
        if postgres(uid, sessions).await == "0" {
            break;
        }
        assert!(attempt < 200, "the foreign app database session did not end");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let verified = backup_command(&controller, config, "verify-portable")
        .arg(&bundle)
        .output()
        .await
        .unwrap();
    assert!(verified.status.success());
    assert_eq!(verified.stdout, b"replace\n");

    // Interrupt the replay after the retirement. The resumed restore continues
    // for the same backup as on an empty target.
    fs::set_permissions(app_socket, fs::Permissions::from_mode(0o700)).unwrap();
    let interrupted = backup_status(&controller, config, "restore-portable", &bundle).await;
    fs::set_permissions(app_socket, socket_permissions).unwrap();
    assert!(!interrupted);
    let journal: Value = serde_json::from_slice(
        &fs::read("/var/lib/rentnerproxy/app-manager/journal.json").unwrap(),
    )
    .unwrap();
    assert_eq!(journal["installations"], json!({}));
    assert!(backup_status(&controller, config, "restore-portable", &bundle).await);
    assert_database(uid).await;
    assert_eq!(
        postgres(
            uid,
            &format!("SET ROLE rp_app_{uid}; SELECT count(*) FROM app.recovery_sentinel;")
        )
        .await,
        "1",
        "a replaced app keeps none of the writes made after the backup"
    );
    manager = start_manager(
        &controller,
        config,
        &installer.token,
        Some(&installation_id),
    )
    .await;
    let replaced = manager_status().await.unwrap()[&installation_id].clone();
    assert_eq!(replaced["active"], second["version"]);
    let replaced_generation = replaced["generation"].as_u64().unwrap();
    assert_eq!(
        read_greeting(&installation_id, replaced_generation).await,
        PERSISTED_GREETING
    );
    assert_database(uid).await;
    halt(&mut manager).await;
    authority.kill().await.unwrap();

    let architecture = if cfg!(target_arch = "x86_64") {
        "linux-amd64"
    } else {
        "linux-arm64"
    };
    let evidence = json!({
        "schemaVersion": 1,
        "architecture": architecture,
        "appId": APP_ID,
        "installationId": installation_id,
        "freshTarget": true,
        "network": "none",
        "appStateFormat": 2,
        "releases": expected["releases"],
        "corruptBackupRejected": true,
        "interruptedRecoveryResumed": true,
        "olderCatalogAdvanced": true,
        "retryAccepted": true,
        "restored": {
            "version": second["version"],
            "generation": restored_generation,
            "greetingVerified": true,
            "databaseVerified": true,
        },
        "rolledBack": {
            "version": first["version"],
            "generation": rolled_back_generation,
            "greetingVerified": true,
            "databaseVerified": true,
        },
        "restarted": {
            "version": first["version"],
            "generation": rolled_back_generation + 1,
            "greetingVerified": true,
            "databaseVerified": true,
        },
        "replaced": {
            "untrackedStorageRejected": true,
            "interruptedRetirementResumed": true,
            "interruptedReplacementResumed": true,
            "version": second["version"],
            "generation": replaced_generation,
            "greetingVerified": true,
            "databaseVerified": true,
        },
    });
    fs::write(report, serde_json::to_vec_pretty(&evidence).unwrap()).unwrap();
}
