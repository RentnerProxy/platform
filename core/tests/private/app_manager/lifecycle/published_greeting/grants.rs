//! Approved capabilities of signed Greeting releases through the real app manager.
//!
//! Three releases repackage the official Greeting 1.0.1 archive with capabilities. 1.1.0 and
//! 1.2.0 publish notifications and read proxy hosts, and 1.3.0 also probes upstreams. One fresh
//! appliance state installs with the Owner's approval, carries it to an update, refuses an update
//! that requests more until the Owner approves it, revokes a grant from the live generation,
//! rolls back, restarts and reinstalls. The authority stub records every grant publication.

use super::distribution::{self, Distribution};
use super::repackage::{Repackaged, generation, installation, offer, repackage};
use super::*;
use marketplace_artifacts::digest;

const NOTIFY: (&str, &str) = ("notifications.publish.v1", "installation");
const READ: (&str, &str) = ("proxy.hosts.read.v1", "proxyHosts");
const PROBE: (&str, &str) = ("diagnostics.upstream.probe.v1", "proxyHosts");
/// Support grants that the platform derives for any release with capabilities.
const SUPPORT: [(&str, &str); 2] = [
    ("app.events.subscribe", "installation"),
    ("app.audit.record", "installation"),
];
/// Two platform proxy host IDs the Owner selects, in sorted order.
const HOSTS: [&str; 2] = [
    "2f9c4b1e-6a3d-4e8f-9b7c-0d1e2f3a4b5c",
    "8a7b6c5d-4e3f-4a1b-9c8d-7e6f5a4b3c2d",
];

/// The repackaged releases in publication order with the capabilities they request.
const RELEASES: [(&str, &[(&str, &str)]); 3] = [
    ("1.1.0", &[NOTIFY, READ]),
    ("1.2.0", &[NOTIFY, READ]),
    ("1.3.0", &[NOTIFY, READ, PROBE]),
];

fn capability((id, scope): (&str, &str)) -> Value {
    json!({"id": id, "scope": scope})
}

fn repackaged() -> [Repackaged; 3] {
    RELEASES.map(|(version, capabilities)| Repackaged {
        version,
        fields: json!({
            "capabilities": capabilities.iter().copied().map(capability).collect::<Vec<_>>(),
        }),
        files: Vec::new(),
    })
}

/// The grants a release lists for `capabilities`, in the order the catalog derives them.
fn requested(capabilities: &[(&str, &str)]) -> Value {
    capabilities
        .iter()
        .chain(&SUPPORT)
        .map(|&item| json!({"capability": capability(item), "allowService": true}))
        .collect()
}

/// The Owner's approval of a release that requests `capabilities`, reading `read` and probing
/// `probe`. The installation's own grants name no resource; the core fills it in.
fn approval(capabilities: &[(&str, &str)], read: &[&str], probe: &[&str]) -> Value {
    let mut items = Vec::new();
    for &item in capabilities.iter().chain(&SUPPORT) {
        let hosts = match item {
            READ => read,
            PROBE => probe,
            _ => {
                items.push(json!({"capability": capability(item), "allowService": true}));
                continue;
            }
        };
        items.extend(hosts.iter().map(|host| {
            json!({"capability": capability(item), "resourceId": host, "allowService": true})
        }));
    }
    items.into()
}

/// The grants the core publishes for that approval, in its stable order.
fn granted(id: &str, read: &[&str], probe: &[&str]) -> Value {
    let grant = |(capability_id, scope): (&str, &str), resource: &str| {
        json!({
            "capability": {"id": capability_id, "scope": scope},
            "resourceId": resource,
            "allowService": true,
        })
    };
    let mut grants = vec![grant(SUPPORT[1], id), grant(SUPPORT[0], id)];
    grants.extend(probe.iter().map(|&host| grant(PROBE, host)));
    grants.push(grant(NOTIFY, id));
    grants.extend(read.iter().map(|&host| grant(READ, host)));
    grants.into()
}

fn publication(generation: u64, activated: bool, grants: &Value) -> Value {
    json!({"generation": generation, "activated": activated, "grants": grants})
}

/// Submit a lifecycle `request` that the catalog must refuse with `status` before it starts.
async fn refuse(request: &Value, status: u16) {
    let (actual, body) = send_ui("POST", "/v1/catalog/lifecycle", Some(request)).await;
    assert_eq!(actual, status, "{body}");
}

#[tokio::test]
#[ignore = "requires native Linux, root, the published Greeting fixture and isolated PostgreSQL"]
async fn privileged_published_greeting_grants() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    require_isolated_state();
    distribution::require_loopback_hosts();
    let controller = PathBuf::from(std::env::var_os("RENTNERPROXY_TEST_CONTROLLER").unwrap());
    let fixture_path = PathBuf::from(std::env::var_os("RP_GREETING_FIXTURE").unwrap());
    let report_path = PathBuf::from(std::env::var_os("RP_GREETING_GRANTS_REPORT").unwrap());
    let mut fixture = crate::app_install::tests::published_greeting::prepare(&fixture_path);
    let installer = InstallerFixture::new(&fixture.root);
    let releases = repackage(&mut fixture, installer.work.path(), &repackaged());
    let [first, carried, widened] = &releases;
    let (narrow, wide) = (RELEASES[0].1, RELEASES[2].1);
    let id = format!("app-{}", &digest(APP_ID.as_bytes())[..32]);
    let log = Path::new(APP_API_SOCKET).with_file_name("grant-log.jsonl");
    let mut authority = start_authority(&id, Some(&log)).await;
    let hosts = Distribution::start(installer.work.path(), first.files.clone(), &releases);
    let mut manager = start_manager(&controller, &installer.config, &installer.token, None).await;

    // 1. The listing shows what 1.1.0 requests. An install without an approval, or with one
    // that does not match, is refused before anything is downloaded or published.
    let listing = wait_catalog_state("ready").await;
    let entry = listing["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["appId"] == APP_ID && entry["version"] == first.version)
        .expect("signed 1.1.0 release in the catalog");
    assert_eq!(entry["archiveSha256"], first.archive_sha256);
    assert_eq!(entry["availability"], "available", "{entry}");
    assert_eq!(entry["grants"], requested(narrow), "{entry}");
    let install = json!({
        "appId": APP_ID,
        "version": first.version,
        "archiveSha256": first.archive_sha256,
    });
    let since = hosts.requests().len();
    let mut refused_installs = Vec::new();
    for (case, approval) in [
        ("missing", None),
        ("unrequested", Some(approval(wide, &HOSTS, &HOSTS[..1]))),
        ("incomplete", Some(approval(narrow, &[], &[]))),
    ] {
        let mut request = install.clone();
        if let Some(approval) = approval {
            request["approval"] = approval;
        }
        let (status, body) = send_ui("POST", "/v1/catalog/install", Some(&request)).await;
        assert_eq!(status, 422, "{case}: {body}");
        refused_installs.push(json!({"approval": case, "status": status}));
    }
    assert!(hosts.deliveries(since, &first.archive_url).is_empty());
    assert!(grant_log().is_empty());
    let mut request = install.clone();
    request["approval"] = approval(narrow, &HOSTS, &[]);
    let (status, body) = send_ui("POST", "/v1/catalog/install", Some(&request)).await;
    assert_eq!(status, 202, "{body}");
    let installed_view = wait_install("installed").await;
    let installed = running_installation(&installed_view, &id).clone();
    assert_eq!(installed["version"], first.version);
    let both = granted(&id, &HOSTS, &[]);
    assert_eq!(installed["grants"], both);
    let installed_generation = generation(&installed);
    assert_eq!(
        grant_log(),
        [publication(installed_generation, false, &both)],
        "only the installed generation received the approved grants"
    );
    save_greeting(&id, installed_generation, PERSISTED_GREETING).await;

    // 2. 1.2.0 requests nothing new, so the update carries the approval.
    let before = offer(&hosts, carried, &mut manager, &controller, &installer, &id).await;
    assert_eq!(before["updateRequiresApproval"], false, "{before}");
    assert_eq!(
        last_grants(),
        publication(generation(&before), false, &both),
        "the restarted generation received the approval again"
    );
    post_lifecycle(&lifecycle_request(
        "update",
        &before,
        Some(&before["update"]),
    ))
    .await;
    let carried_view = wait_lifecycle("update", "succeeded").await;
    let carried_row = running_installation(&carried_view, &id).clone();
    assert_eq!(carried_row["version"], carried.version);
    assert_eq!(carried_row["grants"], both);
    let carried_generation = generation(&carried_row);
    assert_eq!(carried_generation, generation(&before) + 1);
    assert_eq!(last_grants(), publication(carried_generation, false, &both));
    assert_eq!(
        read_greeting(&id, carried_generation).await,
        PERSISTED_GREETING
    );

    // 3. 1.3.0 also probes upstreams. Without an approval, or with the carried one, the update
    // stops before staging and the running generation keeps its grants.
    let before = offer(&hosts, widened, &mut manager, &controller, &installer, &id).await;
    assert_eq!(before["updateRequiresApproval"], true, "{before}");
    let update = lifecycle_request("update", &before, Some(&before["update"]));
    let status_before = manager_status().await.unwrap()[&id].clone();
    let (since, published) = (hosts.requests().len(), grant_log().len());
    let mut stale = update.clone();
    stale["approval"] = approval(narrow, &HOSTS, &[]);
    refuse(&update, 422).await;
    refuse(&stale, 422).await;
    assert!(hosts.deliveries(since, &widened.archive_url).is_empty());
    assert_eq!(grant_log().len(), published);
    let status_after = manager_status().await.unwrap()[&id].clone();
    assert_eq!(status_after, status_before);
    assert_eq!(status_after["candidate"], Value::Null);
    let declined = running_installation(&catalog_view().await, &id).clone();
    assert_eq!(generation(&declined), generation(&before));
    assert_eq!(declined["grants"], both);
    let mut approved = update.clone();
    approved["approval"] = approval(wide, &HOSTS, &HOSTS[..1]);
    post_lifecycle(&approved).await;
    let widened_view = wait_lifecycle("update", "succeeded").await;
    assert_eq!(
        hosts.deliveries(since, &widened.archive_url),
        [widened.archive_size_bytes]
    );
    let widened_row = running_installation(&widened_view, &id).clone();
    assert_eq!(widened_row["version"], widened.version);
    let probing = granted(&id, &HOSTS, &HOSTS[..1]);
    assert_eq!(widened_row["grants"], probing);
    let widened_generation = generation(&widened_row);
    assert_eq!(widened_generation, generation(&before) + 1);
    assert_eq!(
        last_grants(),
        publication(widened_generation, false, &probing)
    );

    // 4. Revoking one host replaces the grants of the live generation without a restart.
    let mut revoke = lifecycle_request("revoke", &widened_row, None);
    revoke["grants"] = json!([{"capability": capability(READ), "resourceId": HOSTS[1]}]);
    post_lifecycle(&revoke).await;
    let revoked_view = wait_lifecycle("revoke", "succeeded").await;
    let revoked_row = running_installation(&revoked_view, &id).clone();
    let reduced = granted(&id, &HOSTS[..1], &HOSTS[..1]);
    assert_eq!(generation(&revoked_row), widened_generation);
    assert_eq!(revoked_row["grants"], reduced);
    assert_eq!(
        last_grants(),
        publication(widened_generation, true, &reduced)
    );
    refuse(&revoke, 409).await;

    // 5. The rollback restores 1.2.0 with its stored approval, which also lost the host.
    post_lifecycle(&lifecycle_request(
        "rollback",
        &revoked_row,
        Some(&revoked_row["previous"]),
    ))
    .await;
    let rolled_back_view = wait_lifecycle("rollback", "succeeded").await;
    let rolled_back = running_installation(&rolled_back_view, &id).clone();
    assert_eq!(rolled_back["version"], carried.version);
    let remaining = granted(&id, &HOSTS[..1], &[]);
    assert_eq!(rolled_back["grants"], remaining);
    let rollback_generation = generation(&rolled_back);
    assert_eq!(rollback_generation, widened_generation + 1);
    assert_eq!(
        last_grants(),
        publication(rollback_generation, false, &remaining)
    );
    assert_eq!(
        read_greeting(&id, rollback_generation).await,
        PERSISTED_GREETING
    );

    // 6. A manager restart publishes the same approval again, and 1.3.0 still needs one.
    halt(&mut manager).await;
    manager = start_manager(&controller, &installer.config, &installer.token, Some(&id)).await;
    let restarted_view = wait_catalog_state("ready").await;
    let restarted = running_installation(&restarted_view, &id).clone();
    let restarted_generation = generation(&restarted);
    assert_eq!(restarted_generation, rollback_generation + 1);
    assert_eq!(restarted["grants"], remaining);
    assert_eq!(
        restarted["update"],
        json!({"version": widened.version, "archiveSha256": widened.archive_sha256})
    );
    assert_eq!(restarted["updateRequiresApproval"], true, "{restarted}");
    assert_eq!(
        last_grants(),
        publication(restarted_generation, false, &remaining)
    );

    // 7. After an uninstall, reinstalling 1.3.0 needs the Owner's approval again.
    post_lifecycle(&lifecycle_request("uninstall", &restarted, None)).await;
    let removed_view = wait_lifecycle("uninstall", "succeeded").await;
    let removed = installation(&removed_view, &id).clone();
    assert_eq!(removed["state"], "removed", "{removed}");
    wait_catalog_state("ready").await;
    let target = json!({"version": widened.version, "archiveSha256": widened.archive_sha256});
    let reinstall = lifecycle_request("reinstall", &removed, Some(&target));
    let published = grant_log().len();
    refuse(&reinstall, 422).await;
    assert_eq!(grant_log().len(), published);
    let mut approved = reinstall.clone();
    approved["approval"] = approval(wide, &HOSTS[1..], &HOSTS[1..]);
    post_lifecycle(&approved).await;
    let reinstalled_view = wait_lifecycle("reinstall", "succeeded").await;
    let reinstalled = running_installation(&reinstalled_view, &id).clone();
    assert_eq!(reinstalled["version"], widened.version);
    assert_eq!(reinstalled["previous"], Value::Null);
    let reselected = granted(&id, &HOSTS[1..], &HOSTS[1..]);
    assert_eq!(reinstalled["grants"], reselected);
    let reinstalled_generation = generation(&reinstalled);
    assert!(reinstalled_generation > restarted_generation);
    assert_eq!(
        last_grants(),
        publication(reinstalled_generation, false, &reselected)
    );
    assert_eq!(
        read_greeting(&id, reinstalled_generation).await,
        PERSISTED_GREETING,
        "reinstalling must open the retained greeting"
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
        "installationId": id,
        "repackagedFrom": {
            "version": base.version,
            "officialCommit": base.official_commit,
            "archiveSha256": base.archive_sha256,
        },
        "releases": releases.iter().zip(RELEASES).map(|(release, (_, capabilities))| json!({
            "version": release.version,
            "catalogRevision": release.catalog_revision,
            "archiveSha256": release.archive_sha256,
            "archiveSizeBytes": release.archive_size_bytes,
            "manifestSha256": release.manifest_sha256,
            "requestedGrants": requested(capabilities),
        })).collect::<Vec<_>>(),
        "install": {
            "refused": refused_installs,
            "archiveRequestedBeforeApproval": false,
            "generation": installed_generation,
            "grants": both,
        },
        "carriedUpdate": {
            "operation": carried_view["lifecycle"],
            "generation": carried_generation,
            "grants": both,
        },
        "widenedUpdate": {
            "refusedWithout": ["missing", "carried"],
            "archiveRequestedBeforeApproval": false,
            "runningGenerationUnchanged": true,
            "operation": widened_view["lifecycle"],
            "generation": widened_generation,
            "grants": probing,
        },
        "revocation": {
            "operation": revoked_view["lifecycle"],
            "liveGeneration": widened_generation,
            "grants": reduced,
        },
        "rollback": {
            "operation": rolled_back_view["lifecycle"],
            "generation": rollback_generation,
            "grants": remaining,
        },
        "restart": {
            "generation": restarted_generation,
            "grants": remaining,
            "updateRequiresApproval": true,
        },
        "reinstall": {
            "refusedWithout": "missing",
            "operation": reinstalled_view["lifecycle"],
            "generation": reinstalled_generation,
            "grants": reselected,
        },
        "publications": grant_log(),
    });
    fs::create_dir_all(report_path.parent().unwrap()).unwrap();
    fs::write(&report_path, serde_json::to_vec_pretty(&evidence).unwrap()).unwrap();
}
