use super::super::*;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Response, StatusCode, service::service_fn};
use hyper_util::rt::TokioIo;
use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::{net::UnixListener, time::Instant};

#[test]
fn cutover_keeps_a_readable_prior_release_and_rotates_by_package_identity() {
    let original = Release {
        version: "1".into(),
        archive_sha256: "a".repeat(64),
        manifest_sha256: "b".repeat(64),
        catalog_revision: 1,
    };
    let next = Release {
        version: "2".into(),
        ..original.clone()
    };
    let mut slot = Slot {
        active: Some(original.clone()),
        ..Default::default()
    };
    let data = Data {
        target_version: 1,
        read_versions: vec![1],
        write_versions: vec![1],
        migrations: vec![],
    };
    assert!(!slot.accepts(&next, Some(&data)));
    assert!(Slot::default().accepts(&next, Some(&data)));
    slot.commit_release(next.clone());
    let refreshed = Release {
        catalog_revision: 9,
        ..next
    };
    slot.candidate = Some(refreshed.clone());
    slot.commit_release(refreshed.clone());
    assert_eq!(slot.previous, Some(original));
    assert_eq!(slot.active, Some(refreshed));
    assert_eq!(slot.candidate, None);
}

#[test]
fn failures_before_activation_preserve_grants_and_legacy_interruptions_remain_conservative() {
    let mut slot = Slot::default();
    slot.require_recovery();
    assert!(!slot.uncertain_grants());
    let reloaded: Slot = serde_json::from_value(serde_json::to_value(slot).unwrap()).unwrap();
    assert!(!reloaded.uncertain_grants());
    let mut legacy = Slot {
        recovery_required: true,
        ..Default::default()
    };
    legacy.require_recovery();
    assert!(legacy.uncertain_grants());
}

#[tokio::test]
async fn start_detects_an_exited_broker_before_the_retirement_tick() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let dir = tempfile::tempdir_in("/root").unwrap();
    let mut child = tokio::process::Command::new("/bin/true").spawn().unwrap();
    assert!(child.wait().await.unwrap().success());
    let mut manager = Manager {
        listener: None,
        config: dir.path().join("missing-config"),
        journal: Journal::open(&dir.path().join("journal")).unwrap(),
        gateway: authority(&dir.path().join("web.sock"), |_, _| StatusCode::NO_CONTENT),
        running: BTreeMap::from([("exited".into(), Running::fixture_child(child))]),
        fence_cursor: String::new(),
    };
    manager
        .journal
        .save(
            "exited",
            Slot {
                app_id: "fixture.exited".into(),
                uid: 53354,
                generation: 1,
                pending_fence: true,
                desired_running: true,
                active: Some(Release {
                    version: "1.0.0".into(),
                    archive_sha256: "a".repeat(64),
                    manifest_sha256: "b".repeat(64),
                    catalog_revision: 1,
                }),
                ..Default::default()
            },
        )
        .unwrap();
    // A real start reaches package recovery and reports the unavailable configuration.
    assert!(
        manager
            .execute(Command::Start {
                installation_id: "exited".into()
            })
            .await
            .is_err()
    );
    let slot = manager.journal.slot("exited").unwrap();
    assert!(slot.recovery_required && !slot.pending_fence);
    assert!(!manager.running.contains_key("exited"));
}

async fn command(socket: &Path, body: Value) -> Value {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::UnixStream::connect(socket).await.unwrap();
    stream
        .write_all(&serde_json::to_vec(&body).unwrap())
        .await
        .unwrap();
    stream.shutdown().await.unwrap();
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn staging_retires_its_exited_broker_before_the_download_finishes() {
    use std::process::Stdio;
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let dir = tempfile::tempdir_in("/root").unwrap();
    let socket = dir.path().join("control.sock");
    let mut child = tokio::process::Command::new("/bin/cat")
        .stdin(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let pipe = child.stdin.take().unwrap();
    let fenced = Arc::new(tokio::sync::Notify::new());
    let observed = fenced.clone();
    let mut manager = Manager {
        listener: Some(Arc::new(UnixListener::bind(&socket).unwrap())),
        config: dir.path().join("offline"),
        journal: Journal::open(&dir.path().join("journal")).unwrap(),
        gateway: authority(&dir.path().join("web.sock"), move |action, body| {
            assert_eq!(body["identity"]["installationId"], "staged");
            if action == "workers-stopped" {
                observed.notify_one();
            }
            StatusCode::NO_CONTENT
        }),
        running: BTreeMap::from([("staged".into(), Running::fixture_child(child))]),
        fence_cursor: String::new(),
    };
    let active = Release {
        version: "1.0.0".into(),
        archive_sha256: "a".repeat(64),
        manifest_sha256: "b".repeat(64),
        catalog_revision: 1,
    };
    manager
        .journal
        .save(
            "staged",
            Slot {
                uid: 53355,
                app_id: "fixture.staged".into(),
                active: Some(active.clone()),
                generation: 1,
                pending_fence: true,
                desired_running: true,
                ..Default::default()
            },
        )
        .unwrap();
    let (release, downloaded) = tokio::sync::oneshot::channel();
    let stage = manager.stage("staged", "fixture.staged".into(), "2.0.0".into(), async {
        downloaded.await.map_err(io::Error::other)?;
        Ok(StagedPackage {
            directory: dir.path().into(),
            manifest: json!({}),
            archive_sha256: "c".repeat(64),
            manifest_sha256: "d".repeat(64),
            catalog_revision: 2,
        })
    });
    let requests = async {
        assert_eq!(
            command(&socket, json!({"action":"status"})).await["result"]["staged"]["running"],
            true
        );
        drop(pipe);
        assert_eq!(
            command(&socket, json!({"action":"stop","installationId":"staged"})).await["ok"],
            false
        );
        fenced.notified().await;
        let state = command(&socket, json!({"action":"status"})).await;
        assert_eq!(state["result"]["staged"]["running"], false);
        assert_eq!(state["result"]["staged"]["recoveryRequired"], true);
        release.send(()).unwrap();
    };
    let (result, ()) = timeout(Duration::from_secs(8), async {
        tokio::join!(stage, requests)
    })
    .await
    .unwrap();
    result.unwrap();
    let slot = manager.journal.slot("staged").unwrap();
    assert!(slot.recovery_required && slot.desired_running && !slot.pending_fence);
    assert_eq!(slot.authority_recorded, Some(true));
    assert_eq!(slot.active, Some(active));
    assert_eq!(slot.candidate.as_ref().unwrap().version, "2.0.0");
}

#[tokio::test]
async fn pending_launch_services_status_unrelated_stop_and_exit_retirement() {
    use tokio::io::AsyncWriteExt;
    use tokio::net::UnixStream;
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let dir = tempfile::tempdir_in("/root").unwrap();
    let socket = dir.path().join("control.sock");
    let done = Arc::new(tokio::sync::Notify::new());
    let third = done.clone();
    let mut manager = Manager {
        listener: Some(Arc::new(UnixListener::bind(&socket).unwrap())),
        config: dir.path().join("offline"),
        journal: Journal::open(&dir.path().join("manager")).unwrap(),
        gateway: authority(&dir.path().join("web.sock"), move |action, body| {
            if action == "workers-stopped" && body["identity"]["installationId"] == "exited" {
                third.notify_one();
            }
            StatusCode::NO_CONTENT
        }),
        running: BTreeMap::new(),
        fence_cursor: String::new(),
    };
    for (id, uid) in [("busy", 53351), ("stop", 53352), ("exited", 53353)] {
        manager
            .journal
            .save(
                id,
                Slot {
                    uid,
                    app_id: format!("fixture.{id}"),
                    generation: 1,
                    pending_fence: true,
                    desired_running: true,
                    ..Default::default()
                },
            )
            .unwrap();
    }
    let (send, finish) = tokio::sync::oneshot::channel();
    let requests = async {
        let mut disconnected = UnixStream::connect(&socket).await.unwrap();
        disconnected
            .write_all(br#"{"action":"status"}"#)
            .await
            .unwrap();
        drop(disconnected);
        assert_eq!(
            command(&socket, json!({"action":"status"})).await["ok"],
            true
        );
        assert_eq!(
            command(&socket, json!({"action":"stop","installationId":"busy"})).await["ok"],
            false
        );
        assert_eq!(
            command(&socket, json!({"action":"stop","installationId":"stop"})).await["ok"],
            true
        );
        done.notified().await;
        send.send(()).unwrap();
    };
    let phase = manager.during(Operation::Launch("busy"), async {
        finish.await.map_err(io::Error::other)
    });
    let ((), result) = timeout(Duration::from_secs(8), async {
        tokio::join!(requests, phase)
    })
    .await
    .unwrap();
    result.unwrap();
    assert!(manager.journal.slot("busy").unwrap().pending_fence);
    assert!(!manager.journal.slot("stop").unwrap().desired_running);
    assert!(!manager.journal.slot("exited").unwrap().pending_fence);
}

fn authority(
    socket: &Path,
    respond: impl Fn(&str, &Value) -> StatusCode + Send + Sync + 'static,
) -> Gateway {
    let web = UnixListener::bind(socket).unwrap();
    let respond = Arc::new(respond);
    tokio::spawn(async move {
        loop {
            let (peer, _) = web.accept().await.unwrap();
            let respond = Arc::clone(&respond);
            tokio::spawn(async move {
                let service = service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                    let action = request
                        .uri()
                        .path()
                        .split('/')
                        .next_back()
                        .unwrap()
                        .to_owned();
                    let respond = Arc::clone(&respond);
                    async move {
                        let bytes = request.into_body().collect().await.unwrap().to_bytes();
                        let body = serde_json::from_slice(&bytes).unwrap();
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(respond(&action, &body))
                                .body(Full::new(Bytes::new()))
                                .unwrap(),
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(peer), service)
                    .await;
            });
        }
    });
    Gateway::fixture(socket.to_path_buf(), unsafe { libc::geteuid() })
}

#[tokio::test]
async fn transient_lease_failure_retries_until_confirmation_or_revocation() {
    let dir = tempfile::tempdir().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let gateway = authority(&dir.path().join("web.sock"), move |action, _| {
        assert_eq!(action, "renew");
        match seen.fetch_add(1, Ordering::SeqCst) {
            0 => StatusCode::SERVICE_UNAVAILABLE,
            1 => StatusCode::NO_CONTENT,
            _ => StatusCode::CONFLICT,
        }
    });
    let short = Duration::from_millis(10);
    let renewal = runtime::Renewal::with_timing(
        gateway,
        json!({}),
        Instant::now() + Duration::from_secs(1),
        short,
        short,
    );
    timeout(Duration::from_secs(2), async {
        while !renewal.finished() {
            sleep(short).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}

#[tokio::test(start_paused = true)]
async fn activation_extends_the_confirmed_window_during_transient_renewal_failure() {
    let dir = tempfile::tempdir().unwrap();
    // Keep the virtual clock stationary during the real Unix socket handshakes.
    let (manual_clock, release_clock) = std::sync::mpsc::channel::<()>();
    let clock_guard = tokio::task::spawn_blocking(move || {
        let _ = release_clock.recv();
    });
    let registration = Instant::now() + Duration::from_secs(1);
    let recovered = Arc::new(tokio::sync::Notify::new());
    let seen = recovered.clone();
    let unavailable = Arc::new(tokio::sync::Notify::new());
    let failed = unavailable.clone();
    let gateway = authority(&dir.path().join("web.sock"), move |action, _| {
        if action == "activate" {
            StatusCode::NO_CONTENT
        } else if Instant::now() < registration {
            failed.notify_one();
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            seen.notify_one();
            StatusCode::NO_CONTENT
        }
    });
    let short = Duration::from_millis(10);
    let renewal =
        runtime::Renewal::with_timing(gateway.clone(), json!({}), registration, short, short);
    renewal.activate(&gateway, &json!({})).await.unwrap();
    async fn advance_until(signal: &tokio::sync::Notify, window: Duration) {
        timeout(window, async {
            loop {
                tokio::select! {
                    biased;
                    _ = signal.notified() => break,
                    _ = tokio::task::yield_now() => tokio::time::advance(Duration::from_millis(1)).await,
                }
            }
        }).await.unwrap();
    }
    advance_until(&unavailable, Duration::from_secs(1)).await;
    tokio::time::advance(Duration::from_secs(2)).await;
    advance_until(&recovered, Duration::from_secs(3)).await;
    assert!(!renewal.finished());
    drop(manual_clock);
    clock_guard.await.unwrap();
}

#[tokio::test]
async fn drain_retires_authority_while_a_writer_is_stopping_and_waits_for_workers() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let dir = tempfile::tempdir_in("/root").unwrap();
    let retired = Arc::new(tokio::sync::Notify::new());
    let seen = retired.clone();
    let workers = Arc::new(AtomicUsize::new(0));
    let checks = workers.clone();
    let gateway = authority(&dir.path().join("web.sock"), move |action, _| {
        if action == "retire" {
            seen.notify_one();
        }
        if action == "workers-stopped" && checks.fetch_add(1, Ordering::SeqCst) == 0 {
            return StatusCode::CONFLICT;
        }
        StatusCode::NO_CONTENT
    });
    let mut manager = Manager {
        listener: None,
        config: dir.path().join("offline"),
        journal: Journal::open(&dir.path().join("journal")).unwrap(),
        gateway,
        running: BTreeMap::new(),
        fence_cursor: String::new(),
    };
    let uid = 53337;
    manager
        .journal
        .save(
            "a",
            Slot {
                app_id: "fixture.a".into(),
                uid,
                generation: 1,
                pending_fence: true,
                ..Default::default()
            },
        )
        .unwrap();
    let writer = manager.journal.writer(uid).unwrap();
    timeout(Duration::from_secs(2), async {
        let (_, result) = tokio::join!(
            async {
                retired.notified().await;
                drop(writer);
            },
            manager.shutdown()
        );
        result.unwrap();
    })
    .await
    .unwrap();
    assert_eq!(workers.load(Ordering::SeqCst), 2);
    assert!(!manager.journal.slot("a").unwrap().pending_fence);
}

#[tokio::test]
async fn failed_retirement_keeps_other_slots_progressing_and_retries_on_tick() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let dir = tempfile::tempdir_in("/root").unwrap();
    let attempts = AtomicUsize::new(0);
    let gateway = authority(&dir.path().join("web.sock"), move |action, body| {
        if action == "retire"
            && body["identity"]["installationId"] == "a"
            && attempts.fetch_add(1, Ordering::SeqCst) == 0
        {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            StatusCode::NO_CONTENT
        }
    });
    let mut manager = Manager {
        listener: None,
        config: dir.path().join("offline"),
        journal: Journal::open(&dir.path().join("journal")).unwrap(),
        gateway,
        running: BTreeMap::new(),
        fence_cursor: String::new(),
    };
    for (id, uid) in [("a", 53335), ("b", 53336)] {
        manager
            .journal
            .save(
                id,
                Slot {
                    app_id: format!("fixture.{id}"),
                    uid,
                    generation: 1,
                    authority_recorded: Some(false),
                    pending_fence: true,
                    ..Default::default()
                },
            )
            .unwrap();
    }
    assert!(manager.shutdown().await.is_err());
    assert!(manager.journal.slot("a").unwrap().pending_fence);
    assert!(!manager.journal.slot("b").unwrap().pending_fence);
    assert_eq!(
        manager.journal.slot("b").unwrap().authority_recorded,
        Some(true)
    );
    manager.check_exits().await.unwrap();
    assert!(!manager.journal.slot("a").unwrap().pending_fence);
    assert!(manager.running.is_empty());
}
