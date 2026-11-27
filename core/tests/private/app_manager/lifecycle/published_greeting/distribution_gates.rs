//! Bounded distribution gates for the published Greeting releases.
//!
//! One fresh appliance state walks through expired trust metadata, unreachable release
//! assets, unreachable distribution, an expired metadata successor during an offered update,
//! a signed release that requests a new capability, the authentic update with coalesced
//! retries and generation-bound UI and API calls, and a restart without any network.
//! Marketplace and GitHub API endpoints stay blocked throughout.

use super::distribution::{
    self, Distribution, Files, METADATA_HOST, RELEASE_HOST, Served, release_path,
};
use super::*;
use crate::app_install::tests::published_greeting::{PublishedSnapshot, prepare_at};
use crate::app_manager::ui::tests::fixture_asset;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rentnerproxy_app_contracts::Contracts;
use std::collections::BTreeMap;
use time::OffsetDateTime;

const ESCALATED_VERSION: &str = "1.0.2";
const CHECKPOINT: &str = "catalog-checkpoint.json";

fn bump_revision(catalog: &mut Value) {
    let revision = catalog["revision"].as_f64().unwrap() as u64;
    catalog["revision"] = (revision + 1).into();
}

fn next_revision(catalog: &[u8]) -> Vec<u8> {
    let mut catalog: Value = serde_json::from_slice(catalog).unwrap();
    bump_revision(&mut catalog);
    serde_json::to_vec(&catalog).unwrap()
}

/// Add a signed Greeting release whose manifest requests a capability the installed
/// releases never had, and which this appliance cannot grant. No archive exists for it.
fn escalated_catalog(current: &[u8]) -> Vec<u8> {
    let mut catalog: Value = serde_json::from_slice(current).unwrap();
    let mut release = catalog["releases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|release| release["appId"] == APP_ID && release["version"] == "1.0.1")
        .expect("official Greeting 1.0.1 release")
        .clone();
    release["version"] = ESCALATED_VERSION.into();
    for package in release["packages"].as_array_mut().unwrap() {
        let manifest = &mut package["manifest"];
        manifest["version"] = ESCALATED_VERSION.into();
        // Docker inventory has no platform endpoint yet, so no Owner can approve it.
        manifest["capabilities"] =
            json!([{"id": "docker.inventory.observe.v1", "scope": "dockerConnections"}]);
        // A distinct identity keeps the cached 1.0.1 archive from satisfying this release,
        // so any staging attempt would have to request its release asset.
        let identity = format!(
            "unpublished {APP_ID} {ESCALATED_VERSION} {}",
            manifest["target"]
        );
        package["archive"]["sha256"] = marketplace_artifacts::digest(identity.as_bytes()).into();
    }
    catalog["releases"].as_array_mut().unwrap().push(release);
    bump_revision(&mut catalog);
    serde_json::to_vec(&catalog).unwrap()
}

/// The release asset paths of the escalated release. The catalog derives each download URL
/// from the manifest identity, so these differ from every authentic Greeting asset.
fn escalated_asset_paths(catalog: &[u8]) -> Vec<String> {
    let document: Value = serde_json::from_slice(catalog).unwrap();
    let contracts = Contracts::new().unwrap();
    let catalog = contracts.validate_catalog(&document).unwrap();
    let release = catalog
        .releases()
        .iter()
        .find(|release| release["appId"] == APP_ID && release["version"] == ESCALATED_VERSION)
        .expect("escalated Greeting release");
    release["packages"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|package| {
            let target = package["manifest"]["target"].as_str().unwrap();
            let assets = catalog
                .package(APP_ID, ESCALATED_VERSION, target)
                .unwrap()
                .release_assets();
            [assets.archive.url, assets.sbom.url, assets.provenance.url]
        })
        .map(|url| release_path(&url))
        .collect()
}

/// Store a catalog checkpoint as the installer would have accepted it at `accepted_at`.
fn plant_checkpoint(
    store: &Path,
    root: &[u8],
    files: &Files,
    accepted_at: OffsetDateTime,
) -> Vec<u8> {
    let files: BTreeMap<_, _> = files
        .iter()
        .map(|(path, bytes)| (path, STANDARD.encode(bytes)))
        .collect();
    let bytes = serde_json::to_vec(&json!({
        "acceptedAt": accepted_at.unix_timestamp(),
        "pinSha256": marketplace_artifacts::digest(root),
        "files": files,
    }))
    .unwrap();
    let path = store.join(CHECKPOINT);
    fs::write(&path, &bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    bytes
}

fn entry<'a>(view: &'a Value, version: &str) -> &'a Value {
    view["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["appId"] == APP_ID && entry["version"] == version)
        .unwrap_or_else(|| panic!("Greeting {version} in the catalog listing: {view}"))
}

fn versions(view: &Value) -> Vec<&str> {
    view["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| entry["appId"] == APP_ID)
        .map(|entry| entry["version"].as_str().unwrap())
        .collect()
}

fn selection(release: &PublishedSnapshot) -> Value {
    json!({
        "appId": APP_ID,
        "version": release.version,
        "archiveSha256": release.archive_sha256,
    })
}

async fn post_install(selection: &Value) {
    let (status, body) = send_ui("POST", "/v1/catalog/install", Some(selection)).await;
    assert_eq!(status, 202, "{body}");
    assert_eq!(body["status"], "installing");
}

/// Submit a catalog request that the running manager must refuse before accepting work.
async fn refused_submission(path: &str, request: &Value) -> u16 {
    let (status, body) = send_ui("POST", path, Some(request)).await;
    assert_eq!(status, 409, "{path} {request}: {body}");
    status
}

/// The authority fixture records the generation of the last grant publication and rejects
/// any non-empty grant set for Greeting. Every launch publishes the approved, empty set.
fn grants_record() -> String {
    fs::read_to_string(Path::new(APP_API_SOCKET).with_file_name("last-grants-generation")).unwrap()
}

/// Fetch the UI entry document of `generation` and compare it with its staged package.
async fn served_ui(
    id: &str,
    generation: u64,
    store: &Path,
    archive_sha256: &str,
) -> (String, Vec<u8>) {
    let (status, metadata) =
        send_ui("GET", &format!("/v1/apps/{id}/{generation}/metadata"), None).await;
    assert_eq!(status, 200, "{metadata}");
    assert_eq!(metadata["generation"], generation);
    assert_eq!(metadata["archiveSha256"], archive_sha256);
    let entry = metadata["entrypoint"]
        .as_str()
        .and_then(|path| path.strip_prefix("ui/"))
        .expect("UI entrypoint below ui/")
        .to_owned();
    let (status, bytes) =
        fixture_asset(&format!("/v1/apps/{id}/{generation}/assets/{entry}")).await;
    assert_eq!(status, 200);
    let staged = store
        .join("packages")
        .join(archive_sha256)
        .join("ui")
        .join(&entry);
    assert_eq!(bytes, fs::read(staged).unwrap());
    (entry, bytes)
}

/// Everything a refused operation must leave untouched.
#[derive(Debug, PartialEq)]
struct ActiveApp {
    installation: Value,
    manager: Value,
    data: Vec<u8>,
    store: [Vec<OsString>; 2],
    ui: Vec<u8>,
    grants_generation: String,
}

impl ActiveApp {
    async fn observe(view: &Value, id: &str, store: &Path) -> Self {
        let row = running_installation(view, id);
        let generation = row["generation"].as_u64().unwrap();
        let manager = manager_status().await.unwrap()[id].clone();
        assert_eq!(manager["generation"], generation);
        assert_eq!(manager["running"], true);
        assert_eq!(manager["candidate"], Value::Null);
        let uid = manager["uid"].as_u64().unwrap();
        assert_eq!(read_greeting(id, generation).await, PERSISTED_GREETING);
        let archive_sha256 = row["archiveSha256"].as_str().unwrap();
        let (_, ui) = served_ui(id, generation, store, archive_sha256).await;
        let grants_generation = grants_record();
        Self {
            installation: json!({
                "generation": row["generation"],
                "version": row["version"],
                "archiveSha256": row["archiveSha256"],
                "previous": row["previous"],
            }),
            manager,
            data: fs::read(format!(
                "/var/lib/rentnerproxy/apps/{uid}/data/greeting.json"
            ))
            .unwrap(),
            store: package_store_entries(store),
            ui,
            grants_generation,
        }
    }
}

/// Post the offered update and require an explicit `error` that leaves the app untouched.
async fn refused_update(
    hosts: &Distribution,
    request: &Value,
    before: &ActiveApp,
    store: &Path,
    (fault, error): (&str, &str),
) -> (Value, Vec<Served>) {
    let id = request["installationId"].as_str().unwrap();
    let since = hosts.requests().len();
    post_lifecycle(request).await;
    let view = wait_lifecycle("update", "failed").await;
    let failed = &view["lifecycle"];
    assert_eq!(failed["target"], request["target"], "{fault}");
    assert_eq!(failed["error"], error, "{fault}: {failed}");
    assert_eq!(
        &ActiveApp::observe(&view, id, store).await,
        before,
        "{fault} changed the active app"
    );
    let requests = hosts.requests_since(since);
    let evidence = json!({
        "fault": fault,
        "operation": failed,
        "requests": requests,
        "activeUnchanged": true,
    });
    (evidence, requests)
}

/// Submit an update to the escalated release and require a refusal that leaves the active
/// app untouched. Returns the refusal status and the state observed before the submission.
async fn refused_escalation(
    view: &Value,
    id: &str,
    store: &Path,
    target: &Value,
) -> (u16, ActiveApp) {
    let before = ActiveApp::observe(view, id, store).await;
    let status = refused_submission(
        "/v1/catalog/lifecycle",
        &lifecycle_request("update", running_installation(view, id), Some(target)),
    )
    .await;
    assert_eq!(
        ActiveApp::observe(&catalog_view().await, id, store).await,
        before,
        "the escalated update changed the active app"
    );
    (status, before)
}

/// The manager requested signed metadata, and each metadata request was `answered`.
/// An answered refresh reaches the timestamp. An unanswered one stops at its first
/// request, the check for a successor root.
fn metadata_refreshed(requests: &[Served], answered: bool) -> bool {
    let metadata: Vec<_> = requests
        .iter()
        .filter(|request| request.host == METADATA_HOST)
        .collect();
    let reached_timestamp = metadata
        .iter()
        .any(|request| request.path.ends_with("/metadata/timestamp.json"));
    !metadata.is_empty()
        && (reached_timestamp || !answered)
        && metadata
            .iter()
            .all(|request| request.status.is_some() == answered)
}

/// Each release asset request with whether the release host answered it.
fn release_requests(requests: &[Served]) -> Vec<(&str, bool)> {
    requests
        .iter()
        .filter(|request| request.host == RELEASE_HOST)
        .map(|request| (request.path.as_str(), request.status.is_some()))
        .collect()
}

#[tokio::test]
#[ignore = "requires native Linux, root, the published Greeting fixture and isolated PostgreSQL"]
async fn privileged_published_greeting_distribution_gates() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    require_isolated_state();
    distribution::require_loopback_hosts();
    let controller = PathBuf::from(std::env::var_os("RENTNERPROXY_TEST_CONTROLLER").unwrap());
    let fixture_path = PathBuf::from(std::env::var_os("RP_GREETING_FIXTURE").unwrap());
    let report_path = PathBuf::from(std::env::var_os("RP_GREETING_GATES_REPORT").unwrap());

    // Both official releases signed two days ago. Their timestamp expired a day ago.
    let now = OffsetDateTime::now_utc().replace_nanosecond(0).unwrap();
    let signed_at = now - time::Duration::days(2);
    let mut fixture = prepare_at(&fixture_path, signed_at);
    let [first, second] = &fixture.snapshots;
    let expired = second.files.clone();
    let official = fixture.repository.catalog_bytes().to_vec();
    // Renew the timestamp, then publish a revision that adds an escalating release.
    fixture.repository.publish(&official, now);
    let escalated_bytes = escalated_catalog(&official);
    let current = fixture.repository.publish(&escalated_bytes, now).clone();
    let escalated_paths = escalated_asset_paths(&escalated_bytes);
    let (first_path, second_path) = (
        release_path(&first.archive_url),
        release_path(&second.archive_url),
    );
    assert!(!escalated_paths.contains(&first_path) && !escalated_paths.contains(&second_path));
    // A newer revision whose online roles were signed two days ago and have expired.
    let expired_successor = fixture
        .repository
        .sign(&next_revision(&escalated_bytes), signed_at);

    let installation_id = format!(
        "app-{}",
        &marketplace_artifacts::digest(APP_ID.as_bytes())[..32]
    );
    let mut authority = start_authority(&installation_id).await;
    let installer = InstallerFixture::new(&fixture.root);
    let (config, token, store) = (&installer.config, &installer.token, &installer.store);
    let checkpoint = store.join(CHECKPOINT);
    let empty_store: [Vec<OsString>; 2] = Default::default();
    let mut hosts = Distribution::start(installer.work.path(), expired.clone(), &fixture.snapshots);
    let install = selection(first);

    // 1. The appliance accepted this catalog two days ago and the mirror froze since.
    let planted = plant_checkpoint(
        store,
        &fixture.root,
        &expired,
        signed_at + time::Duration::hours(1),
    );
    let mut manager = start_manager(&controller, config, token, None).await;
    let cached = wait_catalog_state("stale").await;
    assert_eq!(versions(&cached), [first.version, second.version]);
    let since = hosts.requests().len();
    post_install(&install).await;
    let expired_install = wait_install("failed").await;
    assert_eq!(
        expired_install["install"]["error"], "installFailed",
        "{expired_install}"
    );
    assert_eq!(expired_install["installations"], json!([]));
    assert_eq!(manager_status().await.unwrap(), json!({}));
    assert_eq!(fs::read(&checkpoint).unwrap(), planted);
    assert_eq!(package_store_entries(store), empty_store);
    let expired_requests = hosts.requests_since(since);
    assert!(
        metadata_refreshed(&expired_requests, true),
        "{expired_requests:?}"
    );
    assert!(
        release_requests(&expired_requests).is_empty(),
        "{expired_requests:?}"
    );
    halt(&mut manager).await;

    // 2. Fresh signed metadata is reachable, release assets are not.
    hosts.serve_metadata(current.clone());
    hosts.set_releases_available(false);
    manager = start_manager(&controller, config, token, None).await;
    let listing = wait_catalog_state("ready").await;
    assert_eq!(
        versions(&listing),
        [first.version, second.version, ESCALATED_VERSION]
    );
    for version in [first.version, second.version] {
        assert_eq!(entry(&listing, version)["availability"], "available");
    }
    let escalated = entry(&listing, ESCALATED_VERSION);
    assert_eq!(escalated["availability"], "grantsRequired");
    let escalated_target = json!({
        "version": ESCALATED_VERSION,
        "archiveSha256": escalated["archiveSha256"],
    });
    let mut escalation_refusals = vec![
        refused_submission(
            "/v1/catalog/install",
            &json!({
                "appId": APP_ID,
                "version": ESCALATED_VERSION,
                "archiveSha256": escalated["archiveSha256"],
            }),
        )
        .await,
    ];
    let since = hosts.requests().len();
    post_install(&install).await;
    let unreachable_install = wait_install("failed").await;
    assert_eq!(
        unreachable_install["install"]["error"], "packageSourceUnavailable",
        "{unreachable_install}"
    );
    assert_eq!(unreachable_install["installations"], json!([]));
    assert_eq!(manager_status().await.unwrap(), json!({}));
    assert_eq!(package_store_entries(store), empty_store);
    // The download reached the release host, which closed it without a response.
    let unreachable_requests = hosts.requests_since(since);
    assert!(
        metadata_refreshed(&unreachable_requests, true),
        "{unreachable_requests:?}"
    );
    assert_eq!(
        release_requests(&unreachable_requests),
        [(first_path.as_str(), false)],
        "{unreachable_requests:?}"
    );

    // 3. Marketplace endpoints stay blocked. Signed metadata and release assets suffice.
    hosts.set_releases_available(true);
    let since = hosts.requests().len();
    post_install(&install).await;
    let installed_view = wait_install("installed").await;
    let installed = running_installation(&installed_view, &installation_id);
    assert_eq!(installed["version"], first.version);
    assert_eq!(installed["archiveSha256"], first.archive_sha256);
    assert_eq!(
        hosts.deliveries(since, &first.archive_url),
        [first.archive_size_bytes]
    );
    let first_generation = installed["generation"].as_u64().unwrap();
    assert_eq!(
        read_greeting(&installation_id, first_generation).await,
        "Hello from RentnerProxy!"
    );
    save_greeting(&installation_id, first_generation, PERSISTED_GREETING).await;
    // The catalog install published Greeting's empty grant set for its first generation.
    assert_eq!(grants_record(), first_generation.to_string());

    let ready = wait_catalog_state("ready").await;
    let active = running_installation(&ready, &installation_id);
    let offered = json!({"version": second.version, "archiveSha256": second.archive_sha256});
    assert_eq!(active["update"], offered);
    // The capability request keeps 1.0.2 out of the offered updates.
    let (status, baseline) =
        refused_escalation(&ready, &installation_id, store, &escalated_target).await;
    escalation_refusals.push(status);
    let update = lifecycle_request("update", active, Some(&offered));

    // 4. Release assets become unreachable while signed metadata stays reachable.
    wait_catalog_state("ready").await;
    hosts.set_releases_available(false);
    let (asset_outage, requests) = refused_update(
        &hosts,
        &update,
        &baseline,
        store,
        ("release-assets-unreachable", "packageSourceUnavailable"),
    )
    .await;
    assert!(metadata_refreshed(&requests, true), "{requests:?}");
    assert_eq!(
        release_requests(&requests),
        [(second_path.as_str(), false)],
        "{requests:?}"
    );

    // 5. Signed metadata becomes unreachable as well. The refresh fails before any download.
    // One unanswered probe of the listed archive tells a full outage from a catalog outage.
    wait_catalog_state("ready").await;
    hosts.set_metadata_available(false);
    let (distribution_outage, requests) = refused_update(
        &hosts,
        &update,
        &baseline,
        store,
        ("distribution-unreachable", "networkUnavailable"),
    )
    .await;
    assert!(metadata_refreshed(&requests, false), "{requests:?}");
    assert_eq!(
        release_requests(&requests),
        [(second_path.as_str(), false)],
        "{requests:?}"
    );

    // 6. During an offered update, the repository serves a newer revision whose online
    // roles expired before it was served. Restart for a listing verified while reachable.
    hosts.set_metadata_available(true);
    hosts.set_releases_available(true);
    halt(&mut manager).await;
    manager = start_manager(&controller, config, token, Some(&installation_id)).await;
    let ready = wait_catalog_state("ready").await;
    let active = running_installation(&ready, &installation_id);
    assert_eq!(active["generation"], first_generation + 1);
    assert_eq!(active["update"], offered);
    let update = lifecycle_request("update", active, Some(&offered));
    let baseline = ActiveApp::observe(&ready, &installation_id, store).await;
    let accepted = fs::read(&checkpoint).unwrap();
    hosts.serve_metadata(expired_successor);
    let (expired_update, requests) = refused_update(
        &hosts,
        &update,
        &baseline,
        store,
        ("expired-metadata-successor", "operationFailed"),
    )
    .await;
    assert!(metadata_refreshed(&requests, true), "{requests:?}");
    assert!(release_requests(&requests).is_empty(), "{requests:?}");
    assert_eq!(fs::read(&checkpoint).unwrap(), accepted);

    // 7. The authentic update replaces backend and UI while the manager keeps running.
    hosts.serve_metadata(current);
    halt(&mut manager).await;
    manager = start_manager(&controller, config, token, Some(&installation_id)).await;
    let ready = wait_catalog_state("ready").await;
    let before = running_installation(&ready, &installation_id);
    let old_generation = before["generation"].as_u64().unwrap();
    assert_eq!(old_generation, first_generation + 2);
    let (ui_entry, previous_ui) = served_ui(
        &installation_id,
        old_generation,
        store,
        &first.archive_sha256,
    )
    .await;
    // Greeting 1.0.0 declares no native view. The platform supplies one for its digests.
    let (status, old_metadata) = send_ui(
        "GET",
        &format!("/v1/apps/{installation_id}/{old_generation}/metadata"),
        None,
    )
    .await;
    assert_eq!(status, 200, "{old_metadata}");
    assert!(
        old_metadata.get("nativePresentation").is_none(),
        "{old_metadata}"
    );
    let update = lifecycle_request("update", before, Some(&offered));
    let since = hosts.requests().len();
    post_lifecycle(&update).await;
    // Repeated clicks while the update runs return the same pending operation. A different
    // lifecycle action or an installation is refused until the update has finished.
    let mut repeated_statuses = Vec::new();
    for _ in 0..2 {
        let (status, body) = send_ui("POST", "/v1/catalog/lifecycle", Some(&update)).await;
        assert_eq!(status, 202, "{body}");
        assert_eq!(body["status"], "pending", "{body}");
        assert_eq!(body["expected"], update["expected"], "{body}");
        assert_eq!(body["target"], offered, "{body}");
        repeated_statuses.push(status);
    }
    let concurrent_refusals = [
        refused_submission(
            "/v1/catalog/lifecycle",
            &lifecycle_request("deactivate", before, None),
        )
        .await,
        refused_submission("/v1/catalog/install", &install).await,
    ];
    let updated_view = wait_lifecycle("update", "succeeded").await;
    let updated = running_installation(&updated_view, &installation_id);
    assert_eq!(updated["version"], second.version);
    assert_eq!(updated["archiveSha256"], second.archive_sha256);
    let new_generation = updated["generation"].as_u64().unwrap();
    assert_eq!(new_generation, old_generation + 1);
    assert_eq!(
        hosts.deliveries(since, &second.archive_url),
        [second.archive_size_bytes]
    );
    let (_, ui) = served_ui(
        &installation_id,
        new_generation,
        store,
        &second.archive_sha256,
    )
    .await;
    // Greeting 1.0.1 changes only its API document, so its entry document is byte-identical.
    // The new generation's metadata carries the native view that 1.0.1 declares.
    let ui_entry_changed = ui != previous_ui;
    assert!(!ui_entry_changed);
    let (status, new_metadata) = send_ui(
        "GET",
        &format!("/v1/apps/{installation_id}/{new_generation}/metadata"),
        None,
    )
    .await;
    assert_eq!(status, 200, "{new_metadata}");
    let presentation = &new_metadata["nativePresentation"];
    assert_eq!(presentation["formatVersion"], 1, "{new_metadata}");
    assert!(
        presentation["pages"]
            .as_array()
            .is_some_and(|pages| !pages.is_empty()),
        "{new_metadata}"
    );
    assert_eq!(
        read_greeting(&installation_id, new_generation).await,
        PERSISTED_GREETING
    );
    // The update carries the empty approval from the install and publishes it for its own
    // generation.
    assert_eq!(grants_record(), new_generation.to_string());
    // UI documents and API calls bound to the replaced generation are rejected.
    let stale_generation = format!("/v1/apps/{installation_id}/{old_generation}");
    let stale_calls = [
        send_ui("GET", &format!("{stale_generation}/metadata"), None)
            .await
            .0,
        fixture_asset(&format!("{stale_generation}/assets/{ui_entry}"))
            .await
            .0,
        send_ui(
            "POST",
            &format!("{stale_generation}/operations/get-greeting"),
            Some(&json!({})),
        )
        .await
        .0,
    ];
    assert_eq!(stale_calls, [412; 3]);
    let ready = wait_catalog_state("ready").await;
    let current_row = running_installation(&ready, &installation_id);
    assert_eq!(current_row["generation"], new_generation);
    assert_eq!(current_row["update"], Value::Null);
    let (status, _) = refused_escalation(&ready, &installation_id, store, &escalated_target).await;
    escalation_refusals.push(status);

    // No request carried credentials, and no asset of the escalated release was requested.
    let requests = hosts.requests();
    assert!(requests.iter().all(Served::anonymous), "{requests:?}");
    assert!(
        requests
            .iter()
            .all(|request| !escalated_paths.contains(&request.path)),
        "{requests:?}"
    );

    // 8. Without any network, the installed app and the cached listing keep working.
    hosts.stop();
    halt(&mut manager).await;
    manager = start_manager(&controller, config, token, Some(&installation_id)).await;
    let offline = wait_catalog_state("stale").await;
    let uncached = |view: &Value| -> Value {
        let mut entries = view["entries"].clone();
        for entry in entries.as_array_mut().unwrap() {
            entry.as_object_mut().unwrap().remove("cached");
        }
        entries
    };
    assert_eq!(uncached(&offline), uncached(&ready));
    // Both downloaded releases stay installable from the store; the escalated one never was.
    for (version, stored) in [
        (first.version, true),
        (second.version, true),
        (ESCALATED_VERSION, false),
    ] {
        assert_eq!(entry(&offline, version)["cached"], stored, "{version}");
    }
    let restarted = running_installation(&offline, &installation_id);
    let restarted_generation = new_generation + 1;
    assert_eq!(restarted["generation"], restarted_generation);
    assert_eq!(restarted["version"], second.version);
    assert_eq!(restarted["update"], Value::Null);
    assert_eq!(
        read_greeting(&installation_id, restarted_generation).await,
        PERSISTED_GREETING
    );
    let (_, offline_ui) = served_ui(
        &installation_id,
        restarted_generation,
        store,
        &second.archive_sha256,
    )
    .await;
    assert_eq!(offline_ui, ui);
    let (status, _) =
        refused_escalation(&offline, &installation_id, store, &escalated_target).await;
    escalation_refusals.push(status);
    halt(&mut manager).await;
    authority.kill().await.unwrap();
    // Count once the manager has stopped, including connections still queued at the
    // listener, so the assertion and the report use the same final value.
    let marketplace_attempts = hosts.finish();
    assert_eq!(marketplace_attempts, 0);

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
        "hosts": {
            "metadata": METADATA_HOST,
            "releases": RELEASE_HOST,
            "blocked": distribution::MARKETPLACE_HOSTS,
        },
        "expiredMetadataInstall": {
            "listing": cached["state"],
            "install": expired_install["install"],
            "checkpointUnchanged": true,
            "requests": expired_requests,
        },
        "unreachableReleaseInstall": {
            "install": unreachable_install["install"],
            "requests": unreachable_requests,
        },
        "marketplaceBlockedInstall": {
            "install": installed_view["install"],
            "generation": first_generation,
        },
        "refusedUpdates": [asset_outage, distribution_outage, expired_update],
        "capabilityEscalation": {
            "version": ESCALATED_VERSION,
            "availability": "grantsRequired",
            "refusedSubmissions": escalation_refusals,
            "assetPaths": escalated_paths,
            "assetRequested": false,
        },
        "updateWithoutRestart": {
            "operation": updated_view["lifecycle"],
            "generations": {"replaced": old_generation, "active": new_generation},
            "uiEntry": ui_entry,
            "uiEntrySha256": marketplace_artifacts::digest(&ui),
            "uiEntryChanged": ui_entry_changed,
            "nativePresentation": {"replaced": false, "active": true},
            "repeatedSubmissions": repeated_statuses,
            "concurrentRefusals": concurrent_refusals,
            "archiveDeliveries": 1,
            "staleGenerationCalls": stale_calls,
        },
        "offlineRestart": {
            "listing": offline["state"],
            "generation": restarted_generation,
            "greetingVerified": true,
            "uiVerified": true,
        },
        "anonymousRequests": requests.len(),
        "marketplaceAttempts": marketplace_attempts,
    });
    fs::create_dir_all(report_path.parent().unwrap()).unwrap();
    fs::write(&report_path, serde_json::to_vec_pretty(&evidence).unwrap()).unwrap();
}
