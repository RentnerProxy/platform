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
    timeout(
        Duration::from_secs(2),
        runtime::renew_lease(
            gateway,
            json!({}),
            Instant::now() + Duration::from_secs(1),
            short,
            short,
        ),
    )
    .await
    .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 3);
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
