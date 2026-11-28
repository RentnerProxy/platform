use super::*;
use serde_json::{Value, json};
use std::{
    ffi::OsString,
    fs::{self, File},
    io::{self, Read, Write},
    os::unix::fs::{PermissionsExt, chown},
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use tokio::process::{Child, Command as Process};

#[path = "published_greeting/data_migrations.rs"]
mod data_migrations;
#[path = "published_greeting/distribution.rs"]
mod distribution;
#[path = "published_greeting/distribution_gates.rs"]
mod distribution_gates;
#[path = "published_greeting/grants.rs"]
mod grants;
#[path = "published_greeting/portable_backup.rs"]
mod portable_backup;
#[path = "published_greeting/repackage.rs"]
mod repackage;

use distribution::{ArchiveResponse, Distribution};

const APP_ID: &str = "rentnerproxy.greeting";
const APP_API_SOCKET: &str = "/run/rentnerproxy/app-api/web.sock";
const APP_UI_SOCKET: &str = "/run/rentnerproxy/app-ui/web.sock";
const PERSISTED_GREETING: &str = "Gude from the published Greeting fixture!";
const NO_PROXY: &str = "raw.githubusercontent.com,github.com,127.0.0.1";
static NEXT_IDEMPOTENCY_KEY: AtomicUsize = AtomicUsize::new(1);

async fn send_ui(method: &str, path: &str, body: Option<&Value>) -> (u16, Value) {
    let bytes = body.map_or_else(Vec::new, |value| serde_json::to_vec(value).unwrap());
    let idempotency = if path.contains("/operations/") {
        format!(
            "Idempotency-Key: fixture-{}\r\n",
            NEXT_IDEMPOTENCY_KEY.fetch_add(1, Ordering::Relaxed)
        )
    } else {
        String::new()
    };
    let headers = format!(
        "{}{}",
        if body.is_some() {
            "Content-Type: application/json\r\n"
        } else {
            ""
        },
        idempotency,
    );
    crate::app_manager::ui::tests::fixture_request(method, path, &headers, &bytes).await
}

async fn catalog_view() -> Value {
    let (status, value) = send_ui("GET", "/v1/catalog", None).await;
    assert_eq!(status, 200, "{value}");
    value
}

async fn wait_catalog_state(expected: &str) -> Value {
    timeout(Duration::from_secs(30), async {
        loop {
            let view = catalog_view().await;
            if view["state"] == expected {
                return view;
            }
            assert_eq!(view["state"], "loading", "Expected {expected}: {view}");
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap()
}

async fn wait_install(expected_status: &str) -> Value {
    timeout(Duration::from_secs(120), async {
        loop {
            let view = catalog_view().await;
            if view["install"]["status"] != "installing" {
                assert_eq!(view["install"]["status"], expected_status, "{view}");
                return view;
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap()
}

async fn wait_lifecycle(action: &str, expected_status: &str) -> Value {
    timeout(Duration::from_secs(120), async {
        loop {
            let view = catalog_view().await;
            if view["lifecycle"]["status"] != "pending" {
                assert_eq!(view["lifecycle"]["action"], action);
                assert_eq!(view["lifecycle"]["status"], expected_status, "{view}");
                return view;
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap()
}

fn running_installation<'a>(view: &'a Value, id: &str) -> &'a Value {
    let row = view["installations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["installationId"] == id)
        .expect("Greeting installation in the catalog view");
    assert_eq!(row["state"], "running", "{row}");
    row
}

fn lifecycle_request(action: &str, installation: &Value, target: Option<&Value>) -> Value {
    let mut request = json!({
        "action": action,
        "installationId": installation["installationId"],
        "expected": {
            "generation": installation["generation"],
            "version": installation["version"],
            "archiveSha256": installation["archiveSha256"],
        },
    });
    if let Some(target) = target {
        request["target"] = target.clone();
    }
    request
}

async fn post_lifecycle(request: &Value) {
    let (status, body) = send_ui("POST", "/v1/catalog/lifecycle", Some(request)).await;
    assert_eq!(status, 202, "{body}");
    assert_eq!(body["status"], "pending");
}

async fn read_greeting(installation_id: &str, generation: u64) -> String {
    let read_path = format!("/v1/apps/{installation_id}/{generation}/operations/get-greeting");
    let (status, value) = send_ui("POST", &read_path, Some(&json!({}))).await;
    assert_eq!(status, 200, "{value}");
    value["greeting"].as_str().unwrap().to_owned()
}

async fn save_greeting(installation_id: &str, generation: u64, greeting: &str) {
    let save_path = format!("/v1/apps/{installation_id}/{generation}/operations/save-greeting");
    let (status, value) = send_ui("POST", &save_path, Some(&json!({"greeting": greeting}))).await;
    assert_eq!(status, 200, "{value}");
    assert_eq!(value["greeting"], greeting);
}

fn package_store_entries(store: &Path) -> [Vec<OsString>; 2] {
    ["archives", "packages"].map(|directory| {
        let mut entries: Vec<_> = match fs::read_dir(store.join(directory)) {
            Ok(entries) => entries.map(|entry| entry.unwrap().file_name()).collect(),
            // The installer creates both directories when it stages its first package.
            Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(error) => panic!("Reading the package store {directory}: {error}"),
        };
        entries.sort_unstable();
        entries
    })
}

async fn start_manager(
    controller: &Path,
    config: &Path,
    token: &Path,
    restoring: Option<&str>,
) -> Child {
    let mut command = Process::new(controller);
    unsafe {
        command.pre_exec(|| {
            libc::umask(0o077);
            Ok(())
        });
    }
    let catalog_ca = config.with_file_name("catalog-ca.pem");
    if catalog_ca.is_file() {
        command.env("SSL_CERT_FILE", catalog_ca);
    }
    let mut child = command
        .arg("--app-manager")
        .arg(config)
        .env(crate::config::CONTROLLER_TOKEN_FILE_ENV, token)
        .env("NO_PROXY", NO_PROXY)
        .env("no_proxy", NO_PROXY)
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    timeout(Duration::from_secs(30), async {
        loop {
            assert!(
                child.try_wait().unwrap().is_none(),
                "manager exited on startup"
            );
            if Path::new(APP_UI_SOCKET).exists()
                && manager_status()
                    .await
                    .is_ok_and(|state| restoring.is_none_or(|id| state[id]["running"] == true))
            {
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    child
}

/// Start the authority stub for `installation_id`. With `grant_log`, it records every grant
/// publication in that file instead of accepting only an empty set before activation.
async fn start_authority(installation_id: &str, grant_log: Option<&Path>) -> Child {
    let api = Path::new(APP_API_SOCKET).parent().unwrap();
    fs::create_dir_all(api).unwrap();
    chown(api, Some(10002), Some(10002)).unwrap();
    fs::set_permissions(api, fs::Permissions::from_mode(0o700)).unwrap();
    let mut process = Process::new(std::env::current_exe().unwrap());
    if let Some(log) = grant_log {
        process.env(GRANT_LOG, log);
    }
    let mut child = process
        .args([
            "--ignored",
            "--exact",
            "app_manager::tests::lifecycle::authority_fixture",
            "--nocapture",
        ])
        .uid(10002)
        .gid(10002)
        .env("RENTNERPROXY_TEST_APP_INSTALLATION", installation_id)
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    timeout(Duration::from_secs(5), async {
        while !Path::new(APP_API_SOCKET).exists() {
            assert!(child.try_wait().unwrap().is_none());
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    child
}

fn require_isolated_state() {
    let manager_state = PathBuf::from("/var/lib/rentnerproxy/app-manager");
    let app_state = PathBuf::from("/var/lib/rentnerproxy/apps");
    let package_store = PathBuf::from("/var/lib/rentnerproxy/published-greeting-store");
    assert!(!manager_state.exists(), "manager state must be isolated");
    assert!(!app_state.exists(), "app data must be isolated");
    assert!(
        !package_store.exists(),
        "catalog package store must be isolated"
    );
    fs::create_dir_all("/run/rentnerproxy").unwrap();
    assert!(
        !Path::new(APP_API_SOCKET).exists(),
        "authority socket already exists"
    );
    assert!(
        !Path::new(APP_UI_SOCKET).exists(),
        "UI socket already exists"
    );
}

struct InstallerFixture {
    work: tempfile::TempDir,
    root: PathBuf,
    config: PathBuf,
    token: PathBuf,
    store: PathBuf,
}

impl InstallerFixture {
    fn new(root_bytes: &[u8]) -> Self {
        // Package installer paths are root-verified; keep them off world-writable /tmp.
        let work = tempfile::tempdir_in("/var/lib/rentnerproxy").unwrap();
        fs::set_permissions(work.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let store = PathBuf::from("/var/lib/rentnerproxy/published-greeting-store");
        fs::create_dir(&store).unwrap();
        fs::set_permissions(&store, fs::Permissions::from_mode(0o711)).unwrap();
        let root = work.path().join("root.json");
        fs::write(&root, root_bytes).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o600)).unwrap();
        let token = work.path().join("controller-token");
        fs::write(&token, b"local-lifecycle-fixture").unwrap();
        fs::set_permissions(&token, fs::Permissions::from_mode(0o400)).unwrap();
        let config = work.path().join("installer.json");
        fs::write(
            &config,
            serde_json::to_vec(&json!({
                "storeDirectory": store,
                "pinnedRoot": root,
                "repositoryUrl": distribution::REPOSITORY_URL,
                "engineCapabilities": [],
            }))
            .unwrap(),
        )
        .unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
        Self {
            work,
            root,
            config,
            token,
            store,
        }
    }
}

#[tokio::test]
#[ignore = "requires native Linux, root, the published Greeting fixture and isolated PostgreSQL"]
async fn privileged_published_greeting_lifecycle() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    require_isolated_state();
    distribution::require_loopback_hosts();
    let controller = PathBuf::from(std::env::var_os("RENTNERPROXY_TEST_CONTROLLER").unwrap());
    let fixture_path = PathBuf::from(std::env::var_os("RP_GREETING_FIXTURE").unwrap());
    let report_path = PathBuf::from(std::env::var_os("RP_GREETING_LIFECYCLE_REPORT").unwrap());
    let fixture = crate::app_install::tests::published_greeting::prepare(&fixture_path);
    let installation_id = format!(
        "app-{}",
        &rentnerproxy_artifacts::digest(APP_ID.as_bytes())[..32]
    );
    let mut authority = start_authority(&installation_id, None).await;

    let installer = InstallerFixture::new(&fixture.root);
    let (config, token, store) = (&installer.config, &installer.token, &installer.store);
    // The latest official snapshot includes both published Greeting releases. The
    // install request selects 1.0.0 explicitly; the same signed catalog offers 1.0.1.
    let mut catalog = Distribution::start(
        installer.work.path(),
        fixture.snapshots[1].files.clone(),
        &fixture.snapshots,
    );
    let mut manager = start_manager(&controller, config, token, None).await;
    let listing = wait_catalog_state("ready").await;
    let first = &fixture.snapshots[0];
    let second = &fixture.snapshots[1];
    let selection = listing["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["appId"] == APP_ID && entry["version"] == first.version)
        .expect("signed 1.0.0 release in the published catalog");
    assert_eq!(selection["archiveSha256"], first.archive_sha256);
    assert!(listing["entries"].as_array().unwrap().iter().any(|entry| {
        entry["appId"] == APP_ID
            && entry["version"] == second.version
            && entry["archiveSha256"] == second.archive_sha256
    }));
    let (status, install) = send_ui(
        "POST",
        "/v1/catalog/install",
        Some(&json!({
            "appId": APP_ID,
            "version": first.version,
            "archiveSha256": first.archive_sha256,
        })),
    )
    .await;
    assert_eq!(status, 202, "{install}");
    let installed_view = wait_install("installed").await;
    let installed = installed_view["install"].clone();
    assert_eq!(installed["status"], "installed");
    assert_eq!(installed["installationId"], installation_id);
    let first_install = running_installation(&installed_view, &installation_id);
    assert_eq!(first_install["version"], first.version);
    assert_eq!(first_install["archiveSha256"], first.archive_sha256);
    let first_generation = first_install["generation"].as_u64().unwrap();
    assert_eq!(
        read_greeting(&installation_id, first_generation).await,
        "Hello from RentnerProxy!",
        "fresh install must expose the published default before any write"
    );
    save_greeting(&installation_id, first_generation, PERSISTED_GREETING).await;
    assert_eq!(
        read_greeting(&installation_id, first_generation).await,
        PERSISTED_GREETING
    );

    // Uninstalling keeps the app data, and reinstalling a listed release opens it again.
    let retained_uid = manager_status().await.unwrap()[&installation_id]["uid"].clone();
    let retained_data = PathBuf::from(format!(
        "/var/lib/rentnerproxy/apps/{}/data/greeting.json",
        retained_uid.as_u64().unwrap()
    ));
    let data_before_removal = fs::read(&retained_data).unwrap();
    post_lifecycle(&lifecycle_request("uninstall", first_install, None)).await;
    let uninstalled_view = wait_lifecycle("uninstall", "succeeded").await;
    let uninstalled = uninstalled_view["installations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["installationId"] == installation_id)
        .expect("Greeting keeps an installation row with its retained data");
    assert_eq!(uninstalled["state"], "removed", "{uninstalled}");
    assert_eq!(uninstalled["version"], first.version);
    assert_eq!(uninstalled["archiveSha256"], first.archive_sha256);
    assert_eq!(fs::read(&retained_data).unwrap(), data_before_removal);
    wait_catalog_state("ready").await;
    let reinstall_target = json!({
        "version": first.version,
        "archiveSha256": first.archive_sha256,
    });
    post_lifecycle(&lifecycle_request(
        "reinstall",
        uninstalled,
        Some(&reinstall_target),
    ))
    .await;
    let reinstalled_view = wait_lifecycle("reinstall", "succeeded").await;
    let reinstalled = running_installation(&reinstalled_view, &installation_id);
    assert_eq!(reinstalled["version"], first.version);
    assert_eq!(reinstalled["archiveSha256"], first.archive_sha256);
    assert_eq!(reinstalled["previous"], Value::Null);
    let reinstalled_generation = reinstalled["generation"].as_u64().unwrap();
    assert!(reinstalled_generation > first_generation);
    assert_eq!(
        manager_status().await.unwrap()[&installation_id]["uid"],
        retained_uid
    );
    assert_eq!(
        read_greeting(&installation_id, reinstalled_generation).await,
        PERSISTED_GREETING,
        "reinstalling must open the retained greeting"
    );
    let removed_generation = first_generation;
    let first_generation = reinstalled_generation;

    let ready = wait_catalog_state("ready").await;
    let before_update = running_installation(&ready, &installation_id);
    assert_eq!(before_update["generation"], first_generation);
    assert_eq!(before_update["version"], first.version);
    assert_eq!(before_update["archiveSha256"], first.archive_sha256);
    let offered = &before_update["update"];
    assert_eq!(offered["version"], second.version);
    assert_eq!(offered["archiveSha256"], second.archive_sha256);
    let update = lifecycle_request("update", before_update, Some(offered));

    let status_before = manager_status().await.unwrap()[&installation_id].clone();
    assert_eq!(status_before["active"], first.version);
    assert_eq!(status_before["running"], true);
    assert_eq!(status_before["recoveryRequired"], false);
    assert_eq!(status_before.get("candidate"), Some(&Value::Null));
    let uid = status_before["uid"].as_u64().unwrap();
    let data_path = PathBuf::from(format!(
        "/var/lib/rentnerproxy/apps/{uid}/data/greeting.json"
    ));
    let saved_data = fs::read(&data_path).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&saved_data).unwrap()["greeting"],
        PERSISTED_GREETING
    );
    let store_before = package_store_entries(store);
    let update_archive = store.join("archives").join(&second.archive_sha256);
    let update_package = store.join("packages").join(&second.archive_sha256);
    assert!(!update_archive.exists());
    assert!(!update_package.exists());
    assert!(second.archive_size_bytes > 1);

    let mut update_failures = Vec::new();
    for (mode, fault, expected_payload_length) in [
        (
            ArchiveResponse::Interrupted,
            "interrupted-download",
            second.archive_size_bytes / 2,
        ),
        (
            ArchiveResponse::SameLengthCorruption,
            "same-length-archive-corruption",
            second.archive_size_bytes,
        ),
    ] {
        catalog.set_archive_response(mode);
        wait_catalog_state("ready").await;
        let since = catalog.requests().len();
        post_lifecycle(&update).await;
        let failed_view = wait_lifecycle("update", "failed").await;
        let failed = &failed_view["lifecycle"];
        assert_eq!(failed["installationId"], installation_id);
        assert_eq!(failed["expected"], update["expected"]);
        assert_eq!(failed["target"], update["target"]);
        assert_eq!(failed["error"], "operationFailed", "{failed}");
        let deliveries = catalog.deliveries(since, &second.archive_url);
        assert_eq!(
            deliveries,
            [expected_payload_length],
            "expected exactly one complete {mode:?} fixture response"
        );
        let sent = deliveries[0];

        let active = running_installation(&failed_view, &installation_id);
        assert_eq!(active["version"], first.version, "{fault}");
        assert_eq!(active["archiveSha256"], first.archive_sha256, "{fault}");
        assert_eq!(active["generation"], first_generation, "{fault}");
        assert_eq!(
            manager_status().await.unwrap()[&installation_id],
            status_before,
            "{fault} changed the manager installation state",
        );
        assert_eq!(package_store_entries(store), store_before, "{fault}");
        let greeting = read_greeting(&installation_id, first_generation).await;
        assert_eq!(greeting, PERSISTED_GREETING, "{fault}");
        assert_eq!(fs::read(&data_path).unwrap(), saved_data, "{fault}");
        update_failures.push(json!({
            "fault": fault,
            "operation": failed,
            "response": {
                "advertisedArchiveBytes": second.archive_size_bytes,
                "servedArchiveBytes": sent,
            },
            "installation": active,
            "candidateStaged": false,
            "archiveCommitted": false,
            "persistedGreeting": greeting,
        }));
    }

    catalog.set_archive_response(ArchiveResponse::Authentic);
    wait_catalog_state("ready").await;
    let since = catalog.requests().len();
    post_lifecycle(&update).await;
    let updated_view = wait_lifecycle("update", "succeeded").await;
    let deliveries = catalog.deliveries(since, &second.archive_url);
    assert_eq!(deliveries, [second.archive_size_bytes]);
    let retry_payload_length = deliveries[0];
    let archived =
        rentnerproxy_artifacts::file_identity(&update_archive, second.archive_size_bytes).unwrap();
    assert_eq!(archived.sha256, second.archive_sha256);
    assert_eq!(archived.size_bytes, second.archive_size_bytes);
    assert!(update_package.is_dir());
    let updated = running_installation(&updated_view, &installation_id);
    assert_eq!(updated["version"], second.version);
    assert_eq!(updated["archiveSha256"], second.archive_sha256);
    assert_eq!(updated["previous"]["version"], first.version);
    assert_eq!(updated["previous"]["archiveSha256"], first.archive_sha256);
    let updated_generation = updated["generation"].as_u64().unwrap();
    assert_eq!(updated_generation, first_generation + 1);
    assert_eq!(
        read_greeting(&installation_id, updated_generation).await,
        PERSISTED_GREETING
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(&data_path).unwrap()).unwrap()["greeting"],
        PERSISTED_GREETING
    );

    let after_backup;
    let before_rollback = if let Some(directory) = std::env::var_os("RP_GREETING_CAPTURE_DIRECTORY")
    {
        portable_backup::capture(
            &controller,
            &installer,
            &mut manager,
            &fixture.snapshots,
            u32::try_from(uid).unwrap(),
            Path::new(&directory),
        )
        .await;
        manager = start_manager(&controller, config, token, Some(&installation_id)).await;
        after_backup = wait_catalog_state("ready").await;
        let continued = running_installation(&after_backup, &installation_id);
        assert_eq!(continued["version"], second.version);
        assert_eq!(continued["archiveSha256"], second.archive_sha256);
        assert_eq!(continued["generation"], updated_generation + 1);
        continued
    } else {
        updated
    };
    catalog.stop();
    let offline_rollback = lifecycle_request(
        "rollback",
        before_rollback,
        Some(&before_rollback["previous"]),
    );
    post_lifecycle(&offline_rollback).await;
    let rolled_back_view = wait_lifecycle("rollback", "succeeded").await;
    let rolled_back = running_installation(&rolled_back_view, &installation_id);
    assert_eq!(rolled_back["version"], first.version);
    assert_eq!(rolled_back["archiveSha256"], first.archive_sha256);
    assert_eq!(rolled_back["previous"]["version"], second.version);
    assert_eq!(
        rolled_back["previous"]["archiveSha256"],
        second.archive_sha256
    );
    let rollback_generation = rolled_back["generation"].as_u64().unwrap();
    assert_eq!(
        rollback_generation,
        before_rollback["generation"].as_u64().unwrap() + 1
    );
    assert_eq!(
        read_greeting(&installation_id, rollback_generation).await,
        PERSISTED_GREETING
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(&data_path).unwrap()).unwrap()["greeting"],
        PERSISTED_GREETING
    );

    halt(&mut manager).await;
    manager = start_manager(&controller, config, token, Some(&installation_id)).await;
    let after_restart = manager_status().await.unwrap()[&installation_id].clone();
    assert_eq!(after_restart["active"], first.version);
    let restarted_generation = rollback_generation + 1;
    assert_eq!(after_restart["generation"], restarted_generation);
    let offline_listing = wait_catalog_state("stale").await;
    // The checkpoint keeps the listing. Both archives are now in the store, so both are cached.
    let cached = |view: &Value| -> Vec<Value> {
        let entries = view["entries"].as_array().unwrap();
        entries
            .iter()
            .map(|entry| entry["cached"].clone())
            .collect()
    };
    let uncached = |view: &Value| -> Value {
        let mut entries = view["entries"].clone();
        for entry in entries.as_array_mut().unwrap() {
            entry.as_object_mut().unwrap().remove("cached");
        }
        entries
    };
    assert_eq!(uncached(&offline_listing), uncached(&listing));
    assert_eq!(cached(&listing), [false, false]);
    assert_eq!(cached(&offline_listing), [true, true]);
    assert_eq!(
        read_greeting(&installation_id, restarted_generation).await,
        PERSISTED_GREETING
    );

    // Uninstall and the separately requested data purge are local and work offline.
    let restarted = running_installation(&offline_listing, &installation_id);
    post_lifecycle(&lifecycle_request("uninstall", restarted, None)).await;
    let removed_view = wait_lifecycle("uninstall", "succeeded").await;
    let removed = removed_view["installations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["installationId"] == installation_id)
        .expect("Greeting keeps an installation row with its retained data");
    assert_eq!(removed["state"], "removed", "{removed}");
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(&data_path).unwrap()).unwrap()["greeting"],
        PERSISTED_GREETING
    );
    post_lifecycle(&lifecycle_request("purge", removed, None)).await;
    let purged_view = wait_lifecycle("purge", "succeeded").await;
    assert!(
        purged_view["installations"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["installationId"] != installation_id),
        "{purged_view}"
    );
    let app_directory = data_path.ancestors().nth(2).unwrap();
    assert_eq!(
        app_directory,
        Path::new(&format!("/var/lib/rentnerproxy/apps/{uid}"))
    );
    assert!(!app_directory.exists(), "purge must erase the app data");
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
        "releases": [
            {
                "version": first.version,
                "officialCommit": first.official_commit,
                "catalogRevision": first.catalog_revision,
                "catalogSha256": first.catalog_sha256,
                "archiveSha256": first.archive_sha256,
                "archiveSizeBytes": first.archive_size_bytes,
                "manifestSha256": first.manifest_sha256,
            },
            {
                "version": second.version,
                "officialCommit": second.official_commit,
                "catalogRevision": second.catalog_revision,
                "catalogSha256": second.catalog_sha256,
                "archiveSha256": second.archive_sha256,
                "archiveSizeBytes": second.archive_size_bytes,
                "manifestSha256": second.manifest_sha256,
            },
        ],
        "operations": [
            {"action": "catalog-install", "version": first.version, "result": "installed"},
            {"action": "greeting-save", "result": "visible"},
            {"action": "catalog-uninstall", "version": first.version, "result": "data-retained"},
            {"action": "catalog-reinstall", "version": first.version, "result": "greeting-restored"},
            {"action": "ui-update", "version": second.version, "result": "updated"},
            {"action": "catalog-tls-server", "result": "stopped-before-rollback"},
            {"action": "ui-rollback", "version": first.version, "result": "rolled-back-offline"},
            {"action": "greeting-after-rollback", "result": "visible-and-persisted"},
            {"action": "manager-restart", "result": "restored-offline"},
            {"action": "catalog-listing-after-restart", "result": "served-from-checkpoint"},
            {"action": "greeting-after-restart", "result": "visible-and-persisted"},
            {"action": "offline-uninstall", "result": "data-retained"},
            {"action": "offline-purge", "result": "data-erased"},
        ],
        "updateFailures": update_failures,
        "authenticatedUpdateRetry": {
            "operation": updated_view["lifecycle"],
            "servedArchiveBytes": retry_payload_length,
            "committedArchiveSha256": archived.sha256,
        },
        "persistedGreeting": PERSISTED_GREETING,
        "generations": {
            "installed": removed_generation,
            "reinstalled": first_generation,
            "updated": updated_generation,
            "rolledBack": rollback_generation,
            "restarted": restarted_generation,
        },
        "catalogServerStoppedBeforeRollback": true,
    });
    let report_parent = report_path.parent().unwrap();
    fs::create_dir_all(report_parent).unwrap();
    fs::write(&report_path, serde_json::to_vec_pretty(&evidence).unwrap()).unwrap();
}
