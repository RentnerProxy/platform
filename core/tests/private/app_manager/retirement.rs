use super::super::*;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Response, StatusCode, service::service_fn};
use hyper_util::rt::TokioIo;
use std::{
    convert::Infallible,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
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
        drains: JoinSet::new(),
        draining: HashMap::new(),
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
    use tokio::io::AsyncWriteExt;
    let mut stream = tokio::net::UnixStream::connect(socket).await.unwrap();
    stream
        .write_all(&serde_json::to_vec(&body).unwrap())
        .await
        .unwrap();
    stream.shutdown().await.unwrap();
    response(stream).await
}

async fn response(mut stream: tokio::net::UnixStream) -> Value {
    use tokio::io::AsyncReadExt;
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn staging_services_status_and_publishes_candidate_while_retirement_is_busy() {
    use std::process::Stdio;
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let dir = tempfile::tempdir_in("/root").unwrap();
    let socket = dir.path().join("control.sock");
    let listener = Arc::new(UnixListener::bind(&socket).unwrap());
    let mut child = tokio::process::Command::new("/bin/cat")
        .stdin(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let pipe = child.stdin.take().unwrap();
    let workers_busy = Arc::new(tokio::sync::Notify::new());
    let allow_acknowledgment = Arc::new(AtomicBool::new(false));
    let retire_calls = Arc::new(AtomicUsize::new(0));
    let mut manager = Manager {
        listener: Some(Arc::clone(&listener)),
        config: dir.path().join("offline"),
        journal: Journal::open(&dir.path().join("journal")).unwrap(),
        gateway: authority(&dir.path().join("web.sock"), {
            let workers_busy = Arc::clone(&workers_busy);
            let allow_acknowledgment = Arc::clone(&allow_acknowledgment);
            let retire_calls = Arc::clone(&retire_calls);
            move |action, body| {
                assert_eq!(body["identity"]["installationId"], "staged");
                assert_eq!(body["identity"]["generation"], 1);
                if action == "retire" {
                    retire_calls.fetch_add(1, Ordering::SeqCst);
                }
                if action == "workers-stopped" && !allow_acknowledgment.load(Ordering::SeqCst) {
                    workers_busy.notify_one();
                    return StatusCode::CONFLICT;
                }
                StatusCode::NO_CONTENT
            }
        }),
        running: BTreeMap::from([("staged".into(), Running::fixture_child(child))]),
        fence_cursor: String::new(),
        drains: JoinSet::new(),
        draining: HashMap::new(),
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
    let (stop_serving, serving) = tokio::sync::oneshot::channel();
    let drive_manager = async {
        manager
            .stage("staged", "fixture.staged".into(), "2.0.0".into(), async {
                downloaded.await.map_err(io::Error::other)?;
                Ok(StagedPackage {
                    directory: dir.path().into(),
                    manifest: json!({}),
                    archive_sha256: "c".repeat(64),
                    manifest_sha256: "d".repeat(64),
                    catalog_revision: 2,
                })
            })
            .await
            .unwrap();
        let slot = manager.journal.slot("staged").unwrap();
        assert!(slot.pending_fence);
        assert_eq!(slot.candidate.as_ref().unwrap().version, "2.0.0");
        tokio::select! {
            result = manager.serve_control(&listener) => panic!("Control stopped: {result:?}"),
            result = serving => result.unwrap(),
        }
        manager.shutdown().await.unwrap();
    };
    let requests = async {
        assert_eq!(
            command(&socket, json!({"action":"status"})).await["result"]["staged"]["running"],
            true
        );
        drop(pipe);
        workers_busy.notified().await;
        timeout(Duration::from_secs(2), async {
            let state = command(&socket, json!({"action":"status"})).await;
            assert_eq!(state["result"]["staged"]["running"], false);
            assert_eq!(state["result"]["staged"]["recoveryRequired"], true);
            assert_eq!(state["result"]["staged"]["candidate"], Value::Null);
            let stop = command(&socket, json!({"action":"stop","installationId":"staged"})).await;
            assert_eq!(stop["ok"], false);
        })
        .await
        .unwrap();
        release.send(()).unwrap();
        let state = timeout(
            Duration::from_secs(2),
            command(&socket, json!({"action":"status"})),
        )
        .await
        .unwrap();
        assert_eq!(state["result"]["staged"]["candidate"], "2.0.0");
        allow_acknowledgment.store(true, Ordering::SeqCst);
        stop_serving.send(()).unwrap();
    };
    timeout(Duration::from_secs(10), async {
        tokio::join!(drive_manager, requests)
    })
    .await
    .unwrap();
    let slot = manager.journal.slot("staged").unwrap();
    assert!(slot.recovery_required && slot.desired_running && !slot.pending_fence);
    assert_eq!(slot.generation, 1);
    assert_eq!(slot.authority_recorded, Some(true));
    assert_eq!(slot.active, Some(active));
    assert_eq!(slot.candidate.as_ref().unwrap().version, "2.0.0");
    assert_eq!(retire_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn stage_services_status_and_broker_exit_during_an_unrelated_stop() {
    use std::process::Stdio;
    use tokio::io::AsyncWriteExt;
    use tokio::net::UnixStream;
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let dir = tempfile::tempdir_in("/root").unwrap();
    let socket = dir.path().join("control.sock");
    let listener = Arc::new(UnixListener::bind(&socket).unwrap());
    let mut child = tokio::process::Command::new("/bin/cat")
        .stdin(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let pipe = child.stdin.take().unwrap();
    let workers_busy = Arc::new(tokio::sync::Notify::new());
    let exited_retired = Arc::new(tokio::sync::Notify::new());
    let allow_stop = Arc::new(AtomicBool::new(false));
    let mut stopped_child = tokio::process::Command::new("/bin/cat")
        .stdin(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let stopped_pipe = stopped_child.stdin.take().unwrap();
    let mut manager = Manager {
        listener: Some(Arc::clone(&listener)),
        config: dir.path().join("offline"),
        journal: Journal::open(&dir.path().join("manager")).unwrap(),
        gateway: authority(&dir.path().join("web.sock"), {
            let workers_busy = Arc::clone(&workers_busy);
            let exited_retired = Arc::clone(&exited_retired);
            let allow_stop = Arc::clone(&allow_stop);
            move |action, body| {
                if action == "workers-stopped" {
                    match body["identity"]["installationId"].as_str().unwrap() {
                        "stop" if !allow_stop.load(Ordering::SeqCst) => {
                            workers_busy.notify_one();
                            return StatusCode::CONFLICT;
                        }
                        "exited" => exited_retired.notify_one(),
                        _ => (),
                    }
                }
                StatusCode::NO_CONTENT
            }
        }),
        running: BTreeMap::from([
            ("exited".into(), Running::fixture_child(child)),
            ("stop".into(), Running::fixture_child(stopped_child)),
        ]),
        fence_cursor: String::new(),
        drains: JoinSet::new(),
        draining: HashMap::new(),
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
                    pending_fence: id != "busy",
                    desired_running: true,
                    ..Default::default()
                },
            )
            .unwrap();
    }
    let (release_stage, finish_stage) = tokio::sync::oneshot::channel();
    let (downloaded, download_finished) = tokio::sync::oneshot::channel();
    let (stage_finished, mut during_finished) = tokio::sync::oneshot::channel();
    let (stop_serving, serving) = tokio::sync::oneshot::channel();
    let drive_manager = async {
        manager
            .during(Operation::Stage("busy"), async {
                finish_stage.await.map_err(io::Error::other)?;
                downloaded.send(()).unwrap();
                Ok(())
            })
            .await
            .unwrap();
        stage_finished.send(()).unwrap();
        tokio::select! {
            result = manager.serve_control(&listener) => panic!("Control stopped: {result:?}"),
            result = serving => result.unwrap(),
        }
        manager.wait_for_drain("exited").await.unwrap();
    };
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
        let stop = command(&socket, json!({"action":"stop","installationId":"stop"}));
        tokio::pin!(stop);
        tokio::select! {
            _ = workers_busy.notified() => (),
            response = &mut stop => panic!("Stop acknowledged before workers stopped: {response}"),
        }
        drop(stopped_pipe);
        drop(pipe);
        timeout(Duration::from_secs(4), async {
            let state = command(&socket, json!({"action":"status"})).await;
            assert_eq!(state["result"]["stop"]["desiredRunning"], false);
            exited_retired.notified().await;
            let state = command(&socket, json!({"action":"status"})).await;
            assert_eq!(state["result"]["exited"]["running"], false);
            assert_eq!(state["result"]["exited"]["recoveryRequired"], true);
        })
        .await
        .unwrap();
        let mut late_stop = UnixStream::connect(&socket).await.unwrap();
        late_stop
            .write_all(br#"{"action":"stop","installationId":"exited"}"#)
            .await
            .unwrap();
        release_stage.send(()).unwrap();
        timeout(Duration::from_secs(2), async {
            download_finished.await.unwrap();
            late_stop.shutdown().await.unwrap();
            let late_response = response(late_stop).await;
            assert_eq!(late_response["ok"], false);
            assert!(
                late_response["error"]
                    .as_str()
                    .unwrap()
                    .contains("in progress")
            );
            assert_eq!(
                command(&socket, json!({"action":"status"})).await["ok"],
                true
            );
            let conflicts = [
                json!({"action":"stop","installationId":"stop"}),
                json!({"action":"start","installationId":"stop"}),
            ];
            for request in conflicts {
                let response = command(&socket, request).await;
                assert_eq!(response["ok"], false);
                assert!(response["error"].as_str().unwrap().contains("in progress"));
            }
            assert_eq!(
                during_finished.try_recv(),
                Err(tokio::sync::oneshot::error::TryRecvError::Empty),
            );
        })
        .await
        .unwrap();
        allow_stop.store(true, Ordering::SeqCst);
        assert_eq!(
            timeout(Duration::from_secs(2), &mut stop).await.unwrap()["ok"],
            true
        );
        timeout(Duration::from_secs(2), during_finished)
            .await
            .unwrap()
            .unwrap();
        stop_serving.send(()).unwrap();
    };
    timeout(Duration::from_secs(10), async {
        tokio::join!(requests, drive_manager)
    })
    .await
    .unwrap();
    let stopped = manager.journal.slot("stop").unwrap();
    assert!(!stopped.desired_running && !stopped.pending_fence);
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
        drains: JoinSet::new(),
        draining: HashMap::new(),
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
        drains: JoinSet::new(),
        draining: HashMap::new(),
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
    manager.check_exits(None).unwrap();
    manager.wait_for_drain("a").await.unwrap();
    assert!(!manager.journal.slot("a").unwrap().pending_fence);
    assert!(manager.running.is_empty());
}

#[tokio::test]
async fn shutdown_retries_failed_inherited_drains_once() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let dir = tempfile::tempdir_in("/root").unwrap();
    let attempts = Arc::new(Mutex::new(BTreeMap::new()));
    let attempted = Arc::new(tokio::sync::Notify::new());
    let gateway = authority(&dir.path().join("web.sock"), {
        let attempts = Arc::clone(&attempts);
        let attempted = Arc::clone(&attempted);
        move |action, body| {
            if action != "retire" {
                return StatusCode::NO_CONTENT;
            }
            let id = body["identity"]["installationId"].as_str().unwrap();
            let mut attempts = attempts.lock().unwrap();
            let count = attempts.entry(id.to_owned()).or_insert(0);
            *count += 1;
            if id == "retry" && *count == 2 {
                StatusCode::NO_CONTENT
            } else {
                if id == "retry" {
                    attempted.notify_one();
                }
                StatusCode::SERVICE_UNAVAILABLE
            }
        }
    });
    let mut manager = Manager {
        listener: None,
        config: dir.path().join("offline"),
        journal: Journal::open(&dir.path().join("journal")).unwrap(),
        gateway,
        running: BTreeMap::new(),
        fence_cursor: String::new(),
        drains: JoinSet::new(),
        draining: HashMap::new(),
    };
    let save = |journal: &mut Journal, id, uid| {
        journal
            .save(
                id,
                Slot {
                    app_id: format!("fixture.{id}"),
                    uid,
                    generation: 1,
                    pending_fence: true,
                    ..Default::default()
                },
            )
            .unwrap();
    };
    save(&mut manager.journal, "retry", 53357);
    save(&mut manager.journal, "inherited-failure", 53358);
    let writer = manager.journal.writer(53357).unwrap();
    manager.check_exits(None).unwrap();
    save(&mut manager.journal, "new-failure", 53359);

    let (result, ()) = timeout(Duration::from_secs(4), async {
        tokio::join!(manager.shutdown(), async {
            attempted.notified().await;
            assert_eq!(attempts.lock().unwrap()["retry"], 1);
            drop(writer);
        })
    })
    .await
    .unwrap();
    let error = result.unwrap_err().to_string();
    assert!(error.contains("inherited-failure") && error.contains("new-failure"));
    assert!(!manager.journal.slot("retry").unwrap().pending_fence);
    assert!(
        manager
            .journal
            .slot("inherited-failure")
            .unwrap()
            .pending_fence
    );
    assert!(manager.journal.slot("new-failure").unwrap().pending_fence);
    assert_eq!(
        *attempts.lock().unwrap(),
        BTreeMap::from([
            ("inherited-failure".to_owned(), 2),
            ("new-failure".to_owned(), 1),
            ("retry".to_owned(), 2),
        ]),
    );
}

#[tokio::test(start_paused = true)]
async fn drain_budget_allows_a_slow_writer_and_postgres_fence() {
    let start = Instant::now();
    let (_cutoff, deadline) = watch::channel(start + DRAIN_IO_BUDGET);
    Manager::drain_until(deadline, async {
        sleep(Duration::from_millis(10_500)).await;
        sleep(Duration::from_millis(6_500)).await;
        Ok(())
    })
    .await
    .unwrap();
    assert!(Instant::now() < start + DRAIN_IO_BUDGET);
    assert!(start + DRAIN_IO_BUDGET < start + SHUTDOWN_BUDGET);
    assert!(start + SHUTDOWN_BUDGET < start + Duration::from_secs(18));
}

#[tokio::test(start_paused = true)]
async fn drain_reuses_in_flight_work_after_deadline_changes() {
    let start = Instant::now();
    let original = start + Duration::from_secs(4);
    let extended = start + Duration::from_secs(7);
    let (cutoff, deadline) = watch::channel(original);
    let (started, running) = tokio::sync::oneshot::channel();
    let work = Manager::drain_until(deadline, async {
        started.send(()).unwrap();
        sleep(Duration::from_secs(6)).await;
        Ok(Instant::now())
    });
    let update = async {
        running.await.unwrap();
        sleep(Duration::from_secs(3)).await;
        cutoff.send_replace(extended);
    };
    let (completed, ()) = tokio::join!(work, update);
    let completed = completed.unwrap();
    assert!(original < completed && completed < extended);
}

#[tokio::test(start_paused = true)]
async fn writer_contention_can_exhaust_the_uid_scan_window() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let dir = tempfile::tempdir_in("/root").unwrap();
    let path = dir.path().join("writer.lock");
    let guard = journal::lock(&path).unwrap();
    let start = Instant::now();
    let (_cutoff, deadline) = watch::channel(start + SCAN_BUDGET + Duration::from_secs(1));
    let called = Arc::new(AtomicBool::new(false));
    let checked = Arc::clone(&called);
    let wait = Manager::wait_writer(path, Some(deadline), move || {
        checked.store(true, Ordering::SeqCst);
        Ok(())
    });
    let (result, ()) = tokio::join!(wait, async {
        sleep(Duration::from_secs(2)).await;
        drop(guard);
    });
    let error = result.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(error.to_string().contains("UID scan"));
    assert!(!called.load(Ordering::SeqCst));
}

#[test]
fn writer_timeout_cancels_a_queued_uid_scan() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .start_paused(true)
        .build()
        .unwrap();
    runtime.block_on(async {
        let dir = tempfile::tempdir_in("/root").unwrap();
        let path = dir.path().join("writer.lock");
        let (started, running) = tokio::sync::oneshot::channel();
        let (release, held) = std::sync::mpsc::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            started.send(()).unwrap();
            let _ = held.recv();
        });
        running.await.unwrap();

        let called = Arc::new(AtomicBool::new(false));
        let checked = Arc::clone(&called);
        let wait = Manager::wait_writer(path.clone(), None, move || {
            checked.store(true, Ordering::SeqCst);
            Ok(())
        });
        tokio::pin!(wait);
        tokio::select! {
            biased;
            _ = &mut wait => panic!("the scan cannot finish while the worker is occupied"),
            () = std::future::ready(()) => (),
        }
        assert_eq!(
            journal::lock(&path).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        tokio::time::advance(Duration::from_secs(12)).await;
        assert_eq!(wait.await.unwrap_err().kind(), io::ErrorKind::TimedOut);

        release.send(()).unwrap();
        blocker.await.unwrap();
        tokio::task::spawn_blocking(|| ()).await.unwrap();
        assert!(!called.load(Ordering::SeqCst));
        journal::lock(&path).unwrap();
    });
}

#[tokio::test]
async fn shutdown_publishes_successful_fences_in_one_batch() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let dir = tempfile::tempdir_in("/root").unwrap();
    let directory = dir.path().join("journal");
    let mut manager = Manager {
        listener: None,
        config: dir.path().join("offline"),
        journal: Journal::open(&directory).unwrap(),
        gateway: authority(&dir.path().join("web.sock"), |_, _| StatusCode::NO_CONTENT),
        running: BTreeMap::new(),
        fence_cursor: String::new(),
        drains: JoinSet::new(),
        draining: HashMap::new(),
    };
    for (id, uid) in [("first", 53360), ("second", 53361)] {
        manager
            .journal
            .save(
                id,
                Slot {
                    app_id: format!("fixture.{id}"),
                    uid,
                    generation: 1,
                    pending_fence: true,
                    ..Default::default()
                },
            )
            .unwrap();
    }
    let second_writer = manager.journal.writer(53361).unwrap();
    let original_cutoff = Instant::now() + Duration::from_secs(5);
    let first = manager
        .begin_drain("first".into(), original_cutoff)
        .unwrap();
    let mut first_deadline = manager.draining[&first].cutoff.subscribe();
    timeout(Duration::from_secs(4), async {
        let (result, ()) = tokio::join!(manager.shutdown(), async {
            first_deadline.changed().await.unwrap();
            assert!(*first_deadline.borrow_and_update() > original_cutoff);
            // The first task was collected, while the other still holds up the batch.
            while first_deadline.changed().await.is_ok() {}
            let state = std::fs::read(directory.join("journal.json")).unwrap();
            let state: Value = serde_json::from_slice(&state).unwrap();
            assert_eq!(state["installations"]["first"]["pendingFence"], true);
            assert_eq!(state["installations"]["second"]["pendingFence"], true);
            drop(second_writer);
        });
        result.unwrap();
    })
    .await
    .unwrap();
    drop(manager);
    let journal = Journal::open(&directory).unwrap();
    assert!(!journal.slot("first").unwrap().pending_fence);
    assert!(!journal.slot("second").unwrap().pending_fence);
}

#[tokio::test]
async fn expired_shutdown_write_preserves_fence_intent() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let dir = tempfile::tempdir_in("/root").unwrap();
    let directory = dir.path().join("journal");
    let mut journal = Journal::open(&directory).unwrap();
    let slot = Slot {
        app_id: "fixture.expired".into(),
        uid: 53362,
        generation: 1,
        pending_fence: true,
        ..Default::default()
    };
    journal.save("expired", slot).unwrap();
    let error = journal
        .save_shutdown(BTreeSet::from(["expired".into()]), Instant::now())
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(journal.slot("expired").unwrap().pending_fence);
    drop(journal);
    let journal = Journal::open(&directory).unwrap();
    assert!(journal.slot("expired").unwrap().pending_fence);
}
