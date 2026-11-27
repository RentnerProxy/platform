use std::{
    convert::Infallible,
    fs,
    os::unix::fs::{self as unix_fs, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, Response, StatusCode, client, server, service::service_fn};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use tokio::{
    net::{UnixListener, UnixStream},
    sync::{mpsc, oneshot},
    time::timeout,
};

use super::*;

#[path = "app_ipc_ui.rs"]
mod root_ui_dispatch;

#[path = "app_ipc_providers.rs"]
mod root_provider_dispatch;

const TOKEN: &str = "Bearer manager-test-token";
const CREDENTIAL: &str = "Bearer native-app-test-token";
const CONTEXT: &str = "/platform/v1/context";
const NOTIFY: &str = "/platform/v1/notifications";
const LEASE: &str = "/internal/v1/app-generations/lease";
const TEST_UID: u32 = 20_451;

struct Scratch(PathBuf);

impl Scratch {
    fn create(parent: &Path) -> Self {
        let mut number = [0; 8];
        rand::fill(&mut number).unwrap();
        let path = parent.join(format!("rp-ipc-{:016x}", u64::from_ne_bytes(number)));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn uid() -> u32 {
    // SAFETY: geteuid requires no arguments.
    unsafe { libc::geteuid() }
}

fn launch(uid: u32, executable: PathBuf, data_directory: PathBuf) -> LaunchConfig {
    LaunchConfig {
        app_id: "test.native".into(),
        installation_id: "installation".into(),
        generation: 9,
        uid,
        gid: uid,
        executable,
        data_directory,
        database_url_file: None,
        runtime_profile: PROFILE.into(),
        app_protocol: ">=1.0.0 <2.0.0".into(),
        platform_api: ">=1.0.0 <1.1.0".into(),
        ui_bridge: None,
        startup_timeout_ms: None,
        process_limit: None,
        providers: Vec::new(),
    }
}

fn lease_expiry(remaining: Duration) -> Value {
    let expires = std::time::SystemTime::now() + remaining;
    json!({ "expiresAt": u64::try_from(expires.duration_since(std::time::UNIX_EPOCH).unwrap().as_millis()).unwrap() })
}

async fn fixture_lease(
    request: Request<hyper::body::Incoming>,
    duration: Duration,
    generation: u64,
) -> Response<Full<Bytes>> {
    assert_eq!(request.uri(), LEASE);
    assert_eq!(request.method(), Method::POST);
    assert_eq!(request.headers()["authorization"], TOKEN);
    let body = request.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        body,
        json!({"identity": {"appId": "test.native", "installationId": "installation",
        "generation": generation, "uid": TEST_UID}})
    );
    Response::new(Full::new(Bytes::from(lease_expiry(duration).to_string())))
}

fn request(
    method: Method,
    path: &str,
    credential: &str,
    generation: &str,
    body: Bytes,
) -> Request<Full<Bytes>> {
    Request::builder()
        .method(method)
        .uri(path)
        .header("host", "localhost")
        .header("authorization", credential)
        .header("x-app-installation", "installation")
        .header("x-app-generation", generation)
        .header("content-type", "application/json")
        .header("x-app-delegation", "valid_actor_token")
        .header("idempotency-key", "request-one")
        .header("x-rentnerproxy-app-id", "spoofed.identity")
        .header("x-rentnerproxy-app-uid", "0")
        .header("cookie", "session=should-not-be-forwarded")
        .body(Full::new(body))
        .unwrap()
}

async fn open(socket: &Path) -> client::conn::http1::SendRequest<Full<Bytes>> {
    let stream = UnixStream::connect(socket).await.unwrap();
    let (sender, connection) = client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(connection);
    sender
}

async fn assert_problem(
    sender: &mut client::conn::http1::SendRequest<Full<Bytes>>,
    request: Request<Full<Bytes>>,
    status: StatusCode,
    code: &str,
) {
    let response = sender.send_request(request).await.unwrap();
    assert_eq!(response.status(), status);
    assert_eq!(
        response.headers()["content-type"],
        "application/problem+json"
    );
    let problem: Value =
        serde_json::from_slice(&response.collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(problem["code"], code);
    assert_eq!(problem["type"], format!("urn:rentnerproxy:problem:{code}"));
    assert_eq!(problem["status"], status.as_u16());
    assert!(record_id(problem["requestId"].as_str().unwrap()));
}

fn test_generation(uid: u32, backend: PathBuf, backend_uid: u32) -> Arc<gateway::Generation> {
    Arc::new(
        gateway::Generation::new(
            &launch(uid, PathBuf::new(), PathBuf::new()),
            digest::digest(
                &digest::SHA256,
                CREDENTIAL.strip_prefix("Bearer ").unwrap().as_bytes(),
            ),
            backend,
            backend_uid,
            HeaderValue::from_static(TOKEN),
        )
        .unwrap(),
    )
}

#[tokio::test]
async fn root_ui_dispatch_uses_only_generation_bound_app_credentials() {
    use std::sync::atomic::{AtomicBool, Ordering};

    if uid() != 0 {
        return;
    }
    let scratch = Scratch::create(&env::temp_dir());
    let authority_socket = scratch.path("authority.sock");
    let authority = UnixListener::bind(&authority_socket).unwrap();
    let revoked = Arc::new(AtomicBool::new(false));
    let authority_revoked = Arc::clone(&revoked);
    let authority_task = tokio::spawn(async move {
        loop {
            let (stream, _) = authority.accept().await.unwrap();
            let revoked = Arc::clone(&authority_revoked);
            let service = service_fn(move |request: Request<hyper::body::Incoming>| {
                let revoked = Arc::clone(&revoked);
                async move {
                    assert_eq!(request.uri(), LEASE);
                    assert_eq!(request.headers()["authorization"], TOKEN);
                    let body = request.into_body().collect().await.unwrap().to_bytes();
                    let body: Value = serde_json::from_slice(&body).unwrap();
                    assert_eq!(body["identity"]["generation"], 9);
                    assert_eq!(body["identity"]["installationId"], "installation");
                    let response = if revoked.load(Ordering::Acquire) {
                        Response::builder()
                            .status(401)
                            .body(Full::new(Bytes::new()))
                            .unwrap()
                    } else {
                        Response::new(Full::new(Bytes::from(
                            lease_expiry(Duration::from_secs(20)).to_string(),
                        )))
                    };
                    Ok::<_, Infallible>(response)
                }
            });
            let _ = server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        }
    });
    let app_socket = scratch.path("app.sock");
    let app = UnixListener::bind(&app_socket).unwrap();
    let app_task = tokio::spawn(async move {
        let (stream, _) = app.accept().await.unwrap();
        let service = service_fn(|request: Request<hyper::body::Incoming>| async move {
            assert_eq!(request.uri(), "/app/v1/api/greeting");
            assert_eq!(
                request.headers()["authorization"],
                "Bearer app-ui-direction"
            );
            assert_eq!(request.headers()["x-app-installation"], "installation");
            assert_eq!(request.headers()["x-app-generation"], "9");
            assert_eq!(request.headers()["idempotency-key"], "request-one");
            assert!(!request.headers().contains_key("x-app-delegation"));
            assert!(!request.headers().contains_key("cookie"));
            let body = request.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(body, Bytes::from_static(br#"{"name":"demo"}"#));
            Ok::<_, Infallible>(
                Response::builder()
                    .header("content-type", "application/json")
                    .body(Full::new(Bytes::from_static(br#"{"greeting":"hello"}"#)))
                    .unwrap(),
            )
        });
        server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .await
            .unwrap();
    });
    let mut generation = test_generation(uid(), authority_socket, uid());
    Arc::get_mut(&mut generation)
        .unwrap()
        .set_app_target(app_socket, "app-ui-direction", true)
        .unwrap();
    let core = scratch.path("core.sock");
    let core_task = tokio::spawn(gateway::serve(
        UnixListener::bind(&core).unwrap(),
        generation,
    ));
    let mut sender = open(&core).await;
    let call = |generation| {
        request(
            Method::POST,
            "/app/v1/api/greeting",
            "Bearer ignored",
            generation,
            Bytes::from_static(br#"{"name":"demo"}"#),
        )
    };
    assert_problem(
        &mut sender,
        call("8"),
        StatusCode::FORBIDDEN,
        "installationContextRejected",
    )
    .await;
    let response = sender.send_request(call("9")).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.collect().await.unwrap().to_bytes(),
        br#"{"greeting":"hello"}"#.as_slice()
    );
    app_task.await.unwrap();
    revoked.store(true, Ordering::Release);
    assert_problem(
        &mut sender,
        call("9"),
        StatusCode::FORBIDDEN,
        "installationContextRejected",
    )
    .await;
    core_task.abort();
    authority_task.abort();
}

#[tokio::test]
async fn authenticates_every_request_and_rebuilds_the_bridge_request() {
    if env::var_os("RENTNERPROXY_APP_BOOTSTRAP_FD").is_some() {
        return;
    }
    let scratch = Scratch::create(&env::temp_dir());
    let backend = scratch.path("gateway.sock");
    let listener = UnixListener::bind(&backend).unwrap();
    let (forwarded, mut received) = mpsc::channel(1);
    let backend_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let handler = service_fn(move |request: Request<hyper::body::Incoming>| {
            let forwarded = forwarded.clone();
            async move {
                let (parts, body) = request.into_parts();
                forwarded
                    .send((parts, body.collect().await.unwrap().to_bytes()))
                    .await
                    .unwrap();
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(202)
                        .body(Full::new(Bytes::new()))
                        .unwrap(),
                )
            }
        });
        server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(stream), handler)
            .await
            .unwrap();
    });
    let socket = scratch.path("core.sock");
    let task = tokio::spawn(gateway::serve(
        UnixListener::bind(&socket).unwrap(),
        test_generation(uid(), backend, uid()),
    ));
    let mut sender = open(&socket).await;
    for (path, credential, generation, status, code) in [
        (
            CONTEXT,
            "Bearer wrong-direction-token",
            "9",
            StatusCode::UNAUTHORIZED,
            "appCredentialRejected",
        ),
        (
            CONTEXT,
            CREDENTIAL,
            "09",
            StatusCode::FORBIDDEN,
            "installationContextRejected",
        ),
        (
            CONTEXT,
            CREDENTIAL,
            "8",
            StatusCode::FORBIDDEN,
            "installationContextRejected",
        ),
        (
            "/health",
            CREDENTIAL,
            "9",
            StatusCode::NOT_FOUND,
            "operationNotFound",
        ),
    ] {
        assert_problem(
            &mut sender,
            request(Method::GET, path, credential, generation, Bytes::new()),
            status,
            code,
        )
        .await;
    }
    for body in [
        Bytes::from_static(br#"{"field":1,"field":2}"#),
        Bytes::from_static(br#"{"field":9007199254740992}"#),
        Bytes::from(format!("{}0{}", "[".repeat(65), "]".repeat(65))),
    ] {
        assert_problem(
            &mut sender,
            request(Method::POST, NOTIFY, CREDENTIAL, "9", body),
            StatusCode::BAD_REQUEST,
            "invalidRequest",
        )
        .await;
    }
    assert_problem(
        &mut sender,
        request(
            Method::POST,
            NOTIFY,
            CREDENTIAL,
            "9",
            Bytes::from(vec![b' '; 1_048_577]),
        ),
        StatusCode::PAYLOAD_TOO_LARGE,
        "payloadTooLarge",
    )
    .await;
    // Hyper may close a connection after the body limit rejects it.
    let mut sender = open(&socket).await;
    let payload = Bytes::from_static(br#"{"message":"valid"}"#);
    assert_eq!(
        sender
            .send_request(request(
                Method::POST,
                NOTIFY,
                CREDENTIAL,
                "9",
                payload.clone()
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::ACCEPTED,
    );
    let (parts, body) = timeout(Duration::from_secs(5), received.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(parts.method, Method::POST);
    assert_eq!(parts.uri, NOTIFY);
    assert_eq!(body, payload);
    assert_eq!(parts.headers["authorization"], TOKEN);
    assert_eq!(parts.headers["x-rentnerproxy-app-id"], "test.native");
    assert_eq!(parts.headers["x-rentnerproxy-app-uid"], uid().to_string());
    assert_eq!(parts.headers["x-app-installation"], "installation");
    assert_eq!(parts.headers["x-app-generation"], "9");
    assert_eq!(parts.headers["x-app-delegation"], "valid_actor_token");
    assert_eq!(parts.headers["idempotency-key"], "request-one");
    assert!(!parts.headers.contains_key("cookie"));
    assert!(!parts.headers.values().any(|value| *value == CREDENTIAL));
    backend_task.await.unwrap();
    task.abort();
}

#[tokio::test]
async fn the_monitoring_class_probe_batch_reaches_the_platform_bridge() {
    if env::var_os("RENTNERPROXY_APP_BOOTSTRAP_FD").is_some() {
        return;
    }
    let scratch = Scratch::create(&env::temp_dir());
    let backend = scratch.path("gateway.sock");
    let listener = UnixListener::bind(&backend).unwrap();
    let (forwarded, mut received) = mpsc::channel(1);
    let backend_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let handler = service_fn(move |request: Request<hyper::body::Incoming>| {
            let forwarded = forwarded.clone();
            async move {
                let (parts, body) = request.into_parts();
                forwarded
                    .send((parts, body.collect().await.unwrap().to_bytes()))
                    .await
                    .unwrap();
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "application/json")
                        .body(Full::new(Bytes::from_static(br#"{"results":[]}"#)))
                        .unwrap(),
                )
            }
        });
        server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(stream), handler)
            .await
            .unwrap();
    });
    let socket = scratch.path("core.sock");
    let task = tokio::spawn(gateway::serve(
        UnixListener::bind(&socket).unwrap(),
        test_generation(uid(), backend, uid()),
    ));
    let mut sender = open(&socket).await;
    const BATCH: &str = "/platform/v1/diagnostics/upstream/batch";
    // The batch is a JSON POST route; other methods and paths below it do not exist.
    for (method, path) in [
        (Method::GET, BATCH),
        (Method::POST, "/platform/v1/diagnostics/upstream/batch/1"),
    ] {
        assert_problem(
            &mut sender,
            request(method, path, CREDENTIAL, "9", Bytes::new()),
            StatusCode::NOT_FOUND,
            "operationNotFound",
        )
        .await;
    }
    let payload = Bytes::from_static(
        br#"{"probes":[{"hostId":"host-1","domain":"app.example.net","timeoutMs":3000}]}"#,
    );
    let response = sender
        .send_request(request(
            Method::POST,
            BATCH,
            CREDENTIAL,
            "9",
            payload.clone(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let (parts, body) = timeout(Duration::from_secs(5), received.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(parts.method, Method::POST);
    assert_eq!(parts.uri, BATCH);
    assert_eq!(body, payload);
    assert_eq!(parts.headers["x-app-installation"], "installation");
    backend_task.await.unwrap();
    task.abort();
}

/// The platform's copy of the shared probe fixtures, pinned to the contract revision it builds
/// against.
#[test]
fn the_platform_tests_classify_probes_with_the_contract_fixtures() {
    let copy: Value = serde_json::from_str(include_str!(
        "../../../web/src/tests/fixtures/app-contracts/upstream-probe-fixtures.json"
    ))
    .unwrap();
    let contract: Value =
        serde_json::from_str(rentnerproxy_app_contracts::UPSTREAM_PROBE_FIXTURES).unwrap();
    assert_eq!(copy, contract);
}

const HANDOFFS: &str = "/platform/v1/legacy-handoffs/";

fn handoff_request(
    method: Method,
    route: &str,
    key: Option<&str>,
    body: Option<&'static [u8]>,
) -> Request<Full<Bytes>> {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("{HANDOFFS}{route}"))
        .header("host", "localhost")
        .header("authorization", CREDENTIAL)
        .header("x-app-installation", "installation")
        .header("x-app-generation", "9");
    if let Some(key) = key {
        builder = builder.header("idempotency-key", key);
    }
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    builder
        .body(Full::new(body.map_or_else(Bytes::new, Bytes::from_static)))
        .unwrap()
}

#[tokio::test]
async fn legacy_handoff_routes_reach_the_platform_bridge_with_their_keys_and_bodies() {
    if env::var_os("RENTNERPROXY_APP_BOOTSTRAP_FD").is_some() {
        return;
    }
    let scratch = Scratch::create(&env::temp_dir());
    let backend = scratch.path("gateway.sock");
    let listener = UnixListener::bind(&backend).unwrap();
    let (forwarded, mut received) = mpsc::channel(8);
    let backend_task = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let forwarded = forwarded.clone();
            tokio::spawn(async move {
                let handler = service_fn(move |request: Request<hyper::body::Incoming>| {
                    let forwarded = forwarded.clone();
                    async move {
                        let (parts, body) = request.into_parts();
                        // Platform refuses begin for a domain without a source; relay it as is.
                        let refused = parts.uri.path().ends_with("/begin");
                        forwarded
                            .send((parts, body.collect().await.unwrap().to_bytes()))
                            .await
                            .unwrap();
                        let (status, media) = if refused {
                            (StatusCode::NOT_FOUND, "application/problem+json")
                        } else {
                            (StatusCode::OK, "application/json")
                        };
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(status)
                                .header("content-type", media)
                                .body(Full::new(Bytes::from_static(br#"{"state":"platform"}"#)))
                                .unwrap(),
                        )
                    }
                });
                let _ = server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), handler)
                    .await;
            });
        }
    });
    let socket = scratch.path("core.sock");
    let task = tokio::spawn(gateway::serve(
        UnixListener::bind(&socket).unwrap(),
        test_generation(uid(), backend, uid()),
    ));
    let mut sender = open(&socket).await;

    // Only the four contract routes exist, and the domain must be a provider profile.
    for (method, route) in [
        (Method::GET, "monitoring/begin"),
        (Method::GET, "proxy-hosts"),
        (Method::GET, "Monitoring"),
        (Method::GET, ""),
        (Method::POST, "monitoring"),
        (Method::POST, "monitoring/abort"),
        (Method::POST, "monitoring/begin/parts"),
        (Method::POST, "crowdsec-bouncer/commit"),
    ] {
        assert_problem(
            &mut sender,
            handoff_request(method, route, None, None),
            StatusCode::NOT_FOUND,
            "operationNotFound",
        )
        .await;
    }
    // Begin carries no body, while parts and commit need bounded JSON.
    for (route, body) in [
        ("monitoring/begin", &br"{}"[..]),
        ("monitoring/parts", &br#"{"sequence":9007199254740992}"#[..]),
        ("monitoring/commit", &br#"{"digest":"a","digest":"b"}"#[..]),
    ] {
        assert_problem(
            &mut sender,
            handoff_request(Method::POST, route, Some("key-1"), Some(body)),
            StatusCode::BAD_REQUEST,
            "invalidRequest",
        )
        .await;
    }
    let mut untyped = handoff_request(Method::POST, "monitoring/parts", None, None);
    *untyped.body_mut() = Full::new(Bytes::from_static(br#"{"sequence":0}"#));
    assert_problem(
        &mut sender,
        untyped,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "unsupportedMediaType",
    )
    .await;
    assert!(received.try_recv().is_err());

    // Hyper may close a connection whose body the broker did not read.
    let mut sender = open(&socket).await;
    let commit =
        br#"{"digest":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}"#;
    let part = br#"{"digest":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08","sequence":0}"#;
    for (method, route, key, body, status) in [
        (Method::GET, "monitoring", None, None, StatusCode::OK),
        (
            Method::POST,
            "docker-discovery/begin",
            Some("begin-1"),
            None,
            StatusCode::NOT_FOUND,
        ),
        (
            Method::POST,
            "load-balancer/parts",
            None,
            Some(&part[..]),
            StatusCode::OK,
        ),
        (
            Method::POST,
            "crowdsec/commit",
            Some("commit-1"),
            Some(&commit[..]),
            StatusCode::OK,
        ),
    ] {
        let response = sender
            .send_request(handoff_request(method.clone(), route, key, body))
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        let media = if status == StatusCode::OK {
            "application/json"
        } else {
            "application/problem+json"
        };
        assert_eq!(response.headers()["content-type"], media);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(
            response.collect().await.unwrap().to_bytes(),
            &br#"{"state":"platform"}"#[..]
        );
        let (parts, forwarded_body) = timeout(Duration::from_secs(5), received.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(parts.method, method);
        assert_eq!(parts.uri, format!("{HANDOFFS}{route}").as_str());
        assert_eq!(forwarded_body, body.unwrap_or_default());
        assert_eq!(
            parts
                .headers
                .get("idempotency-key")
                .map(|value| value.to_str().unwrap()),
            key
        );
        assert_eq!(
            parts.headers.contains_key("content-type"),
            body.is_some(),
            "{route}"
        );
        assert_eq!(parts.headers["authorization"], TOKEN);
        assert_eq!(parts.headers["x-rentnerproxy-app-id"], "test.native");
        assert_eq!(parts.headers["x-app-installation"], "installation");
        assert_eq!(parts.headers["x-app-generation"], "9");
    }
    assert!(received.try_recv().is_err());
    backend_task.abort();
    task.abort();
}

#[tokio::test]
async fn verifies_both_unix_peer_identities() {
    if env::var_os("RENTNERPROXY_APP_BOOTSTRAP_FD").is_some() {
        return;
    }
    let scratch = Scratch::create(&env::temp_dir());
    let backend = scratch.path("gateway.sock");
    let _backend = UnixListener::bind(&backend).unwrap();
    let wrong_app = scratch.path("app-peer.sock");
    let app_task = tokio::spawn(gateway::serve(
        UnixListener::bind(&wrong_app).unwrap(),
        test_generation(uid() + 1, backend.clone(), uid()),
    ));
    assert_problem(
        &mut open(&wrong_app).await,
        request(Method::GET, CONTEXT, CREDENTIAL, "9", Bytes::new()),
        StatusCode::FORBIDDEN,
        "installationContextRejected",
    )
    .await;
    app_task.abort();

    let wrong_gateway = scratch.path("gateway-peer.sock");
    let gateway_task = tokio::spawn(gateway::serve(
        UnixListener::bind(&wrong_gateway).unwrap(),
        test_generation(uid(), backend, uid() + 1),
    ));
    assert_problem(
        &mut open(&wrong_gateway).await,
        request(Method::GET, CONTEXT, CREDENTIAL, "9", Bytes::new()),
        StatusCode::SERVICE_UNAVAILABLE,
        "platformUnavailable",
    )
    .await;
    gateway_task.abort();
}

#[tokio::test]
async fn closing_generation_cancels_event_stream_in_both_directions() {
    use hyper::body::{Body, Frame};
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    struct FixtureStream {
        event: Option<Bytes>,
        closed: Option<oneshot::Sender<()>>,
    }

    impl Body for FixtureStream {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
            match self.event.take() {
                Some(event) => Poll::Ready(Some(Ok(Frame::data(event)))),
                None => Poll::Pending,
            }
        }
    }

    impl Drop for FixtureStream {
        fn drop(&mut self) {
            if let Some(closed) = self.closed.take() {
                let _ = closed.send(());
            }
        }
    }

    let scratch = Scratch::create(&env::temp_dir());
    let backend = scratch.path("gateway.sock");
    let listener = UnixListener::bind(&backend).unwrap();
    let (upstream_close, closed) = oneshot::channel();
    let runner = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let upstream_close = std::sync::Mutex::new(Some(upstream_close));
        let service = service_fn(move |request: Request<hyper::body::Incoming>| {
            assert_eq!(request.headers()["last-event-id"], "event_cursor");
            std::future::ready(Ok::<_, Infallible>(
                Response::builder()
                    .header("content-type", "text/event-stream")
                    .body(FixtureStream {
                        event: Some(Bytes::from_static(b"id: resumed\n\n")),
                        closed: upstream_close.lock().unwrap().take(),
                    })
                    .unwrap(),
            ))
        });
        let _ = server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .await;
    });
    let socket = scratch.path("core.sock");
    let broker = tokio::spawn(gateway::serve(
        UnixListener::bind(&socket).unwrap(),
        test_generation(uid(), backend, uid()),
    ));
    let mut request = request(
        Method::GET,
        "/platform/v1/events",
        CREDENTIAL,
        "9",
        Bytes::new(),
    );
    request
        .headers_mut()
        .insert("last-event-id", HeaderValue::from_static("event_cursor"));
    let mut sender = open(&socket).await;
    let response = sender.send_request(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "text/event-stream");
    let mut body = response.into_body();
    let event = timeout(Duration::from_secs(5), body.frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        event.into_data().unwrap(),
        Bytes::from_static(b"id: resumed\n\n")
    );
    broker.abort();
    broker.await.unwrap_err();
    assert!(
        timeout(Duration::from_secs(5), body.frame())
            .await
            .unwrap()
            .is_some_and(|frame| frame.is_err())
    );
    timeout(Duration::from_secs(5), closed)
        .await
        .unwrap()
        .unwrap();
    runner.await.unwrap();
}

#[tokio::test]
async fn database_renewal_extends_the_broker_lease_until_authority_revokes_it() {
    let scratch = Scratch::create(&env::temp_dir());
    let socket = scratch.path("lease.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let (rejection_sent, rejected) = oneshot::channel();
    let authority = tokio::spawn(async move {
        let original = Bytes::from(lease_expiry(Duration::from_millis(700)).to_string());
        for (status, remaining_ms) in [
            (StatusCode::OK, 0),
            (StatusCode::OK, 0),
            (StatusCode::OK, 0),
            (StatusCode::OK, 4000),
            (StatusCode::UNAUTHORIZED, 0),
        ] {
            let (stream, _) = listener.accept().await.unwrap();
            let service = service_fn(|request| {
                let original = original.clone();
                async move {
                    let mut response =
                        fixture_lease(request, Duration::from_millis(remaining_ms), 9).await;
                    if status == StatusCode::OK && remaining_ms == 0 {
                        *response.body_mut() = Full::new(original);
                    }
                    *response.status_mut() = status;
                    Ok::<_, Infallible>(response)
                }
            });
            server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await
                .unwrap();
        }
        rejection_sent.send(()).unwrap();
    });
    let generation = test_generation(TEST_UID, socket, uid());
    let initial = lease::check(&generation).await.unwrap().unwrap();
    let broker = tokio::spawn(async move { lease::maintain(&generation, initial).await });
    timeout(Duration::from_secs(6), rejected)
        .await
        .expect("the broker must renew and recheck past the original lease")
        .unwrap();
    assert!(tokio::time::Instant::now() >= initial);
    timeout(Duration::from_secs(1), broker)
        .await
        .expect("a trusted 401 must stop the broker before the renewed lease expires")
        .unwrap();
    timeout(Duration::from_secs(3), authority)
        .await
        .unwrap()
        .unwrap();
}

#[test]
fn an_elapsed_start_deadline_cannot_be_serialized_for_watchdog_handoff() {
    assert_eq!(
        process::LaunchDeadline::from_instant(tokio::time::Instant::now())
            .err()
            .unwrap()
            .raw_os_error(),
        Some(libc::ETIMEDOUT),
    );
}

#[tokio::test]
async fn watchdog_can_detect_pending_revocation_before_reactor_delivery() {
    use tokio::io::AsyncWriteExt;

    let (manager, mut writer) = UnixStream::pair().unwrap();
    let manager = process::ManagerPipe::Stream(manager);
    assert!(!manager.revocation_pending().unwrap());
    writer.write_all(b"x").await.unwrap();
    assert!(manager.revocation_pending().unwrap());
    drop(writer);
    assert!(manager.revocation_pending().unwrap());
}

#[tokio::test]
async fn an_unreachable_lease_authority_cannot_keep_an_expired_broker_alive() {
    let scratch = Scratch::create(&env::temp_dir());
    let socket = scratch.path("lease.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let authority = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let service = service_fn(|request| async {
            Ok::<_, Infallible>(fixture_lease(request, Duration::from_millis(500), 9).await)
        });
        server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .await
            .unwrap();
        let (_stream, _) = listener.accept().await.unwrap();
        std::future::pending::<()>().await;
    });
    let generation = test_generation(TEST_UID, socket, uid());
    let initial = lease::check(&generation).await.unwrap().unwrap();
    timeout(
        Duration::from_secs(2),
        lease::maintain(&generation, initial),
    )
    .await
    .unwrap();
    assert!(tokio::time::Instant::now() >= initial);
    authority.abort();
}

#[test]
fn launch_config_accepts_only_unique_known_provider_profiles() {
    let strings = |values: &[&str]| values.iter().map(|v| (*v).to_owned()).collect::<Vec<_>>();
    assert!(valid_provider_profiles(&[]));
    assert!(valid_provider_profiles(&strings(&PROVIDER_PROFILES)));
    assert!(valid_provider_profiles(&strings(&["dns", "monitoring"])));
    assert!(!valid_provider_profiles(&strings(&["dns", "dns"])));
    assert!(!valid_provider_profiles(&strings(&["unknown"])));
    assert!(!valid_provider_profiles(&strings(&["DNS"])));
    let mut seven = strings(&PROVIDER_PROFILES);
    seven.push("seventh".into());
    assert!(!valid_provider_profiles(&seven));

    let mut config = launch(TEST_UID, PathBuf::new(), PathBuf::new());
    config.providers = strings(&["monitoring", "monitoring"]);
    assert!(
        config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("Invalid app provider profiles")
    );
    config.providers = strings(&["not-a-profile"]);
    assert!(
        config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("Invalid app provider profiles")
    );
}

#[test]
fn launch_frames_default_to_no_declared_providers_and_reject_unknown_members() {
    let mut frame = json!({
        "appId": "test.native", "installationId": "installation", "generation": 9,
        "uid": TEST_UID, "gid": TEST_UID, "executable": "/bin/app", "dataDirectory": "/data",
        "databaseUrlFile": null, "runtimeProfile": PROFILE, "appProtocol": ">=1.0.0 <2.0.0",
        "platformApi": ">=1.0.0 <2.0.0", "uiBridge": null,
        "startupTimeoutMs": null, "processLimit": null,
    });
    let absent: LaunchConfig = serde_json::from_value(frame.clone()).unwrap();
    assert!(absent.providers.is_empty());
    frame["providers"] = json!(["monitoring", "dns"]);
    let declared: LaunchConfig = serde_json::from_value(frame.clone()).unwrap();
    assert_eq!(declared.providers, ["monitoring", "dns"]);
    frame["provider"] = json!([]);
    assert!(serde_json::from_value::<LaunchConfig>(frame).is_err());
}

struct Posted {
    method: Method,
    uri: String,
    authorization: String,
    body: Value,
}

struct Readiness {
    result: Option<io::Result<()>>,
    posted: Vec<Posted>,
}

#[test]
fn provider_results_must_answer_their_invocation() {
    let pair = |profile: &str, request: Value, result: Value| {
        gateway::provider_result_matches(
            &json!({"profile": profile, "payload": request}),
            &json!({"profile": profile, "payload": result}),
        )
    };
    let observed = |count: usize| json!(vec![json!({}); count]);
    // Lists stay within the requested limit, however JSON writes that integral limit.
    for limit in ["2", "2.0", "2e0"] {
        let request: Value = serde_json::from_str(&format!(r#"{{"limit":{limit}}}"#)).unwrap();
        assert!(pair(
            "monitoring",
            request.clone(),
            json!({"samples": observed(2)})
        ));
        assert!(!pair(
            "monitoring",
            request,
            json!({"samples": observed(3)})
        ));
        let discovery: Value = serde_json::from_str(&format!(
            r#"{{"connectionId":"docker-one","limit":{limit}}}"#
        ))
        .unwrap();
        assert!(pair(
            "docker-discovery",
            discovery.clone(),
            json!({"connectionId": "docker-one", "observations": observed(2)})
        ));
        assert!(!pair(
            "docker-discovery",
            discovery,
            json!({"connectionId": "docker-one", "observations": observed(3)})
        ));
    }
    let discovery = json!({"connectionId": "docker-one", "limit": 1});
    assert!(pair(
        "docker-discovery",
        discovery.clone(),
        json!({"connectionId": "docker-one", "observations": observed(1)})
    ));
    assert!(!pair(
        "docker-discovery",
        discovery.clone(),
        json!({"connectionId": "docker-two", "observations": []})
    ));
    assert!(!pair(
        "docker-discovery",
        discovery,
        json!({"connectionId": "docker-one", "observations": observed(2)})
    ));
    // An applied load-balancer revision is the requested one; other outcomes keep the old one.
    let apply = json!({"action": "apply", "contributionId": "pool", "revision": "7"});
    let status = |status: &str, revision: &str| {
        json!({"contributionId": "pool",
            "revisionStatus": {"status": status, "appliedRevision": revision}})
    };
    assert!(pair("load-balancer", apply.clone(), status("applied", "7")));
    assert!(!pair(
        "load-balancer",
        apply.clone(),
        status("applied", "6")
    ));
    assert!(pair(
        "load-balancer",
        apply.clone(),
        status("rejected", "6")
    ));
    assert!(!pair(
        "load-balancer",
        apply,
        json!({"contributionId": "other", "revisionStatus": {"status": "unchanged"}})
    ));
    assert!(pair(
        "load-balancer",
        json!({"action": "readStatus", "contributionId": "pool"}),
        status("applied", "9")
    ));
    // DNS, OIDC and CrowdSec results concern the same action and resource.
    let check = json!({"action": "check", "challengeId": "challenge"});
    assert!(pair(
        "dns",
        check.clone(),
        json!({"action": "check", "challengeId": "challenge"})
    ));
    assert!(!pair(
        "dns",
        check.clone(),
        json!({"action": "cleanup", "challengeId": "challenge"})
    ));
    assert!(!pair(
        "dns",
        check,
        json!({"action": "check", "challengeId": "other"})
    ));
    assert!(pair(
        "oidc",
        json!({"transactionId": "login"}),
        json!({"transactionId": "login"})
    ));
    assert!(!pair(
        "oidc",
        json!({"transactionId": "login"}),
        json!({"transactionId": "other"})
    ));
    let logs = json!({"action": "consumeLogs", "batchId": "batch"});
    assert!(pair(
        "crowdsec",
        logs.clone(),
        json!({"action": "consumeLogs", "batchId": "batch"})
    ));
    assert!(!pair(
        "crowdsec",
        logs.clone(),
        json!({"action": "consumeLogs", "batchId": "other"})
    ));
    assert!(!pair("crowdsec", logs, json!({"action": "evaluate"})));
    assert!(pair(
        "crowdsec",
        json!({"action": "evaluate", "proxyHostId": "host"}),
        json!({"action": "evaluate"})
    ));
    // The result belongs to the invoked profile, which must be a known one.
    assert!(!gateway::provider_result_matches(
        &json!({"profile": "oidc", "payload": {"transactionId": "login"}}),
        &json!({"profile": "dns", "payload": {"transactionId": "login"}}),
    ));
    assert!(!pair("unknown", json!({}), json!({})));
}

fn registration(id: &str, profile: &str) -> Value {
    json!({"id": id, "profile": profile, "version": "1.0.0"})
}

/// Drive `app_ready` against a fake app and a fake authority on own-UID sockets.
///
/// `ready` are the app's readiness bodies in order, repeating the last one.
/// `statuses` are the authority's replies in order, repeating the last one.
/// `authority_delay` postpones binding the authority socket (connection failures).
/// A `None` result means readiness was still retrying when `patience` elapsed.
async fn exercise_readiness(
    ready: Vec<Value>,
    declared: &[&str],
    statuses: &[u16],
    authority_delay: Duration,
    patience: Duration,
) -> Readiness {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let scratch = Scratch::create(&env::temp_dir());
    let app_socket = scratch.path("app.sock");
    let app = UnixListener::bind(&app_socket).unwrap();
    let ready = Arc::new(ready);
    let ready_served = Arc::new(AtomicUsize::new(0));
    let app_task = tokio::spawn(async move {
        loop {
            let (stream, _) = app.accept().await.unwrap();
            let ready = Arc::clone(&ready);
            let ready_served = Arc::clone(&ready_served);
            let service = service_fn(move |request: Request<hyper::body::Incoming>| {
                let body = match request.uri().path() {
                    "/app/v1/health" => json!({"healthy": true}),
                    "/app/v1/ready" => {
                        let index = ready_served.fetch_add(1, Ordering::Relaxed);
                        ready[index.min(ready.len() - 1)].clone()
                    }
                    path => panic!("Unexpected fixture app path {path}"),
                };
                std::future::ready(Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(
                    body.to_string(),
                )))))
            });
            tokio::spawn(
                server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), service),
            );
        }
    });
    let authority_socket = scratch.path("authority.sock");
    let (sender, mut receiver) = mpsc::unbounded_channel();
    let replies = statuses.to_vec();
    let bind_at = authority_socket.clone();
    let authority_task = tokio::spawn(async move {
        tokio::time::sleep(authority_delay).await;
        let listener = UnixListener::bind(bind_at).unwrap();
        let mut served = 0;
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let status = replies[served.min(replies.len() - 1)];
            served += 1;
            let sender = sender.clone();
            let service = service_fn(move |request: Request<hyper::body::Incoming>| {
                let sender = sender.clone();
                async move {
                    let (parts, body) = request.into_parts();
                    let body = body.collect().await.unwrap().to_bytes();
                    sender
                        .send(Posted {
                            method: parts.method,
                            uri: parts.uri.to_string(),
                            authorization: parts.headers["authorization"]
                                .to_str()
                                .unwrap()
                                .to_owned(),
                            body: serde_json::from_slice(&body).unwrap(),
                        })
                        .unwrap();
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(status)
                            .body(Full::new(Bytes::new()))
                            .unwrap(),
                    )
                }
            });
            let _ = server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        }
    });
    let generation = test_generation(uid(), authority_socket, uid());
    let core_socket = scratch.path("core.sock");
    let bootstrap = Bootstrap {
        format_version: 1,
        app_id: "test.native",
        installation_id: "installation",
        generation: 9,
        runtime_profile: PROFILE,
        versions: Versions {
            app_protocol: VERSION,
            platform_api: VERSION,
            ui_bridge: None,
        },
        app_socket: &app_socket,
        core_socket: &core_socket,
        app_credential: "app-credential",
        core_credential: "core-credential",
    };
    let declared: Vec<String> = declared
        .iter()
        .map(|profile| (*profile).to_owned())
        .collect();
    let result = timeout(
        patience,
        gateway::app_ready(&bootstrap, &generation, uid(), &declared),
    )
    .await
    .ok();
    app_task.abort();
    authority_task.abort();
    let mut posted = Vec::new();
    while let Ok(request) = receiver.try_recv() {
        posted.push(request);
    }
    Readiness { result, posted }
}

fn ready_with(providers: Value) -> Value {
    json!({"ready": true, "protocolVersion": VERSION, "providers": providers})
}

async fn readiness(providers: Value, declared: &[&str], statuses: &[u16]) -> Readiness {
    exercise_readiness(
        vec![ready_with(providers)],
        declared,
        statuses,
        Duration::ZERO,
        Duration::from_secs(5),
    )
    .await
}

#[tokio::test]
async fn invalid_provider_advertisements_are_fatal_and_never_reach_the_authority() {
    let thirty_three: Vec<Value> = (0..33)
        .map(|index| registration(&format!("monitor-{index}"), "monitoring"))
        .collect();
    let mut extra_member = registration("monitor", "monitoring");
    extra_member["extra"] = json!(true);
    let mut numeric_version = registration("monitor", "monitoring");
    numeric_version["version"] = json!(1);
    for (case, providers) in [
        ("too many", json!(thirty_three)),
        (
            "duplicate id",
            json!([
                registration("monitor", "monitoring"),
                registration("monitor", "monitoring")
            ]),
        ),
        ("unknown member", json!([extra_member])),
        (
            "missing member",
            json!([{"id": "monitor", "profile": "monitoring"}]),
        ),
        ("non-string version", json!([numeric_version])),
        ("bad id", json!([registration("Bad Id", "monitoring")])),
        ("empty id", json!([registration("", "monitoring")])),
        (
            "unknown profile",
            json!([registration("monitor", "firewall")]),
        ),
        (
            "undeclared profile",
            json!([registration("monitor", "dns")]),
        ),
        (
            "bad version",
            json!([{"id": "monitor", "profile": "monitoring", "version": "1.0.1"}]),
        ),
        ("not an array", json!({"id": "monitor"})),
        ("not an object", json!(["monitor"])),
    ] {
        let outcome = readiness(providers, &["monitoring"], &[204]).await;
        let error = outcome
            .result
            .unwrap_or_else(|| panic!("{case} must not be retried"))
            .expect_err(case);
        assert_eq!(
            error.to_string(),
            "App advertised invalid provider registrations",
            "{case}"
        );
        assert!(outcome.posted.is_empty(), "{case}");
    }
}

#[tokio::test]
async fn valid_registrations_are_posted_with_the_broker_identity_before_readiness() {
    let thirty_two: Vec<Value> = (0..32)
        .map(|index| registration(&format!("monitor-{index}"), "monitoring"))
        .collect();
    let outcome = readiness(json!(thirty_two), &["monitoring"], &[204]).await;
    outcome.result.unwrap().unwrap();
    assert_eq!(outcome.posted.len(), 1);

    let providers = json!([
        registration("fixture-monitor", "monitoring"),
        registration("second_monitor", "monitoring"),
        registration("edge-dns", "dns"),
    ]);
    let outcome = readiness(providers.clone(), &["dns", "monitoring"], &[204]).await;
    outcome.result.unwrap().unwrap();
    let [posted] = outcome.posted.as_slice() else {
        panic!("exactly one registration request is expected");
    };
    assert_eq!(posted.method, Method::POST);
    assert_eq!(posted.uri, "/internal/v1/app-generations/providers");
    assert_eq!(posted.authorization, TOKEN);
    assert_eq!(
        posted.body,
        json!({
            "identity": {
                "appId": "test.native", "installationId": "installation",
                "generation": 9, "uid": uid(),
            },
            "providers": providers,
        })
    );
}

#[tokio::test]
async fn apps_without_providers_become_ready_without_an_authority_request() {
    let outcome = readiness(json!([]), &[], &[500]).await;
    outcome.result.unwrap().unwrap();
    assert!(outcome.posted.is_empty());
}

#[tokio::test]
async fn authority_rejections_of_provider_registrations_are_fatal() {
    for status in [200, 400, 401, 403, 404, 409] {
        let outcome = readiness(
            json!([registration("monitor", "monitoring")]),
            &["monitoring"],
            &[status],
        )
        .await;
        let error = outcome
            .result
            .unwrap_or_else(|| panic!("{status} must not be retried"))
            .expect_err("registration must be rejected");
        assert_eq!(
            error.to_string(),
            "Platform authority rejected app provider registrations",
            "{status}"
        );
        assert_eq!(outcome.posted.len(), 1, "{status}");
    }
}

#[tokio::test]
async fn transient_authority_failures_retry_the_registration() {
    for status in [500, 503, 408, 429] {
        let outcome = readiness(
            json!([registration("monitor", "monitoring")]),
            &["monitoring"],
            &[status, 204],
        )
        .await;
        outcome.result.expect("retried until success").unwrap();
        assert_eq!(outcome.posted.len(), 2, "{status}");
        assert_eq!(outcome.posted[0].body, outcome.posted[1].body, "{status}");
    }
    // The authority socket does not exist for the first attempts.
    let outcome = exercise_readiness(
        vec![ready_with(json!([registration("monitor", "monitoring")]))],
        &["monitoring"],
        &[204],
        Duration::from_millis(450),
        Duration::from_secs(5),
    )
    .await;
    outcome
        .result
        .expect("connection failures are retried")
        .unwrap();
    assert_eq!(outcome.posted.len(), 1);
}

#[tokio::test]
async fn retries_repeat_the_first_validated_registration() {
    let first = json!([registration("monitor", "monitoring")]);
    for later in [
        json!([]),
        json!([registration("other", "monitoring")]),
        json!([
            registration("other", "monitoring"),
            registration("monitor", "monitoring")
        ]),
    ] {
        let outcome = exercise_readiness(
            vec![ready_with(first.clone()), ready_with(later.clone())],
            &["monitoring"],
            &[503, 204],
            Duration::ZERO,
            Duration::from_secs(5),
        )
        .await;
        outcome.result.expect("retried until success").unwrap();
        assert_eq!(outcome.posted.len(), 2, "{later}");
        for posted in &outcome.posted {
            assert_eq!(posted.body["providers"], first, "{later}");
        }
    }
}

#[tokio::test]
async fn a_compatible_ready_response_without_providers_is_fatal() {
    let outcome = exercise_readiness(
        vec![json!({"ready": true, "protocolVersion": VERSION})],
        &["monitoring"],
        &[204],
        Duration::ZERO,
        Duration::from_secs(5),
    )
    .await;
    let error = outcome
        .result
        .expect("a missing providers member must not be retried")
        .expect_err("a missing providers member is invalid");
    assert_eq!(
        error.to_string(),
        "App advertised invalid provider registrations"
    );
    assert!(outcome.posted.is_empty());
}

#[tokio::test]
async fn an_app_that_is_not_ready_keeps_retrying_without_registration() {
    for ready in [
        json!({"ready": false, "protocolVersion": VERSION, "providers": []}),
        json!({"ready": true, "protocolVersion": "9.9.9", "providers": []}),
        json!({"ready": false, "protocolVersion": VERSION}),
    ] {
        let outcome = exercise_readiness(
            vec![ready],
            &["monitoring"],
            &[204],
            Duration::ZERO,
            Duration::from_millis(700),
        )
        .await;
        assert!(outcome.result.is_none());
        assert!(outcome.posted.is_empty());
    }
}

#[tokio::test]
#[ignore = "requires root inside the isolated IPC test container"]
async fn privileged_generation_launches_restricted_child_and_revokes_listener() {
    assert_eq!(uid(), 0);
    let scratch = Scratch::create(Path::new("/run"));
    fs::set_permissions(&scratch.0, fs::Permissions::from_mode(0o711)).unwrap();
    let fixture = scratch.path("fixture-binary");
    fs::copy(env::current_exe().unwrap(), &fixture).unwrap();
    fs::set_permissions(&fixture, fs::Permissions::from_mode(0o555)).unwrap();
    let executable = scratch.path("fixture");
    fs::write(
        &executable,
        format!(
            "#!/bin/sh\nexec {} --exact app_ipc::tests::restricted_child_fixture > fixture.log 2>&1\n",
            fixture.display()
        ),
    ).unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o555)).unwrap();
    let data = scratch.path("data");
    fs::create_dir(&data).unwrap();
    unix_fs::chown(&data, Some(TEST_UID), Some(TEST_UID)).unwrap();
    fs::set_permissions(&data, fs::Permissions::from_mode(0o700)).unwrap();
    let config = launch(TEST_UID, executable, data.clone());
    config.validate().unwrap();

    let app_root = scratch.path("apps");
    let uid_root = app_root.join(TEST_UID.to_string());
    fs::create_dir(&app_root).unwrap();
    fs::set_permissions(&app_root, fs::Permissions::from_mode(0o711)).unwrap();
    fs::create_dir(&uid_root).unwrap();
    fs::set_permissions(&uid_root, fs::Permissions::from_mode(0o700)).unwrap();
    unix_fs::chown(&uid_root, Some(0), Some(TEST_UID)).unwrap();
    let unpublished = uid_root.join(".identity.pending");
    fs::write(&unpublished, "test.na").unwrap();
    fs::set_permissions(&unpublished, fs::Permissions::from_mode(0o600)).unwrap();
    let backend = scratch.path("gateway.sock");
    let controller = PathBuf::from(env::var_os("RENTNERPROXY_TEST_CONTROLLER").unwrap());
    let listener = UnixListener::bind(&backend).unwrap();
    let backend_task = tokio::spawn(async move {
        use std::sync::atomic::{AtomicBool, Ordering};

        let context_served = AtomicBool::new(false);
        while !context_served.load(Ordering::Relaxed) {
            let (stream, _) = listener.accept().await.unwrap();
            assert_eq!(stream.peer_cred().unwrap().uid(), 0);
            let service = service_fn(|request: Request<hyper::body::Incoming>| {
                let context_served = &context_served;
                async move {
                    if request.uri() == LEASE {
                        return Ok::<_, Infallible>(
                            fixture_lease(request, Duration::from_secs(25), 9).await,
                        );
                    }
                    assert_eq!(request.uri(), CONTEXT);
                    assert_eq!(request.headers()["authorization"], TOKEN);
                    assert_eq!(
                        request.headers()["x-rentnerproxy-app-uid"],
                        TEST_UID.to_string()
                    );
                    context_served.store(true, Ordering::Relaxed);
                    Ok(Response::new(Full::new(Bytes::from_static(
                        br#"{"context":"verified"}"#,
                    ))))
                }
            });
            server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await
                .unwrap();
        }
    });
    let (revoke, stopped) = oneshot::channel::<()>();
    let core = app_root.join(TEST_UID.to_string()).join("9/core.sock");
    let marker = data.join("ready");
    let mut task = tokio::spawn(async move {
        run_generation(
            config,
            RuntimePaths {
                app_root: &app_root,
                gateway_socket: &backend,
                gateway_uid: uid(),
                controller: &controller,
            },
            HeaderValue::from_static(TOKEN),
            async {
                let _ = stopped.await;
            },
        )
        .await
    });
    tokio::select! {
        result = &mut task => panic!("App fixture stopped before readiness: {result:?}, {:?}", fs::read_to_string(data.join("fixture.log"))),
        result = timeout(Duration::from_secs(15), async {
            while !marker.exists() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }) => result.unwrap_or_else(|_| panic!("App fixture did not become ready: {:?}", fs::read_to_string(data.join("fixture.log")))),
    }
    assert!(core.exists());
    revoke.send(()).unwrap();
    timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(UnixStream::connect(core).await.is_err());
    timeout(Duration::from_secs(3), backend_task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        fs::metadata(&uid_root).unwrap().permissions().mode() & 0o777,
        0o710
    );
    assert_eq!(
        fs::read_to_string(uid_root.join("identity")).unwrap(),
        "test.native\ninstallation\n"
    );
    assert!(!unpublished.exists());
}

#[tokio::test]
#[ignore = "requires root and a private /run inside the isolated IPC test container"]
async fn privileged_controller_validates_launch_pipe_and_bootstrap_paths() {
    use std::{
        os::{fd::AsRawFd, unix::process::CommandExt},
        process::Stdio,
    };
    use tokio::{io::AsyncWriteExt, process::Command};

    assert_eq!(uid(), 0);
    let controller = env::var_os("RENTNERPROXY_TEST_CONTROLLER").unwrap();
    let scratch = Scratch::create(Path::new("/run"));
    fs::set_permissions(&scratch.0, fs::Permissions::from_mode(0o711)).unwrap();
    let executable = scratch.path("app");
    fs::write(&executable, "#!/bin/sh\ncat > descriptor.json\n").unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o555)).unwrap();
    let data = scratch.path("data");
    fs::create_dir(&data).unwrap();
    unix_fs::chown(&data, Some(TEST_UID), Some(TEST_UID)).unwrap();
    fs::set_permissions(&data, fs::Permissions::from_mode(0o700)).unwrap();
    let database = data.join("database-url");
    fs::write(&database, "synthetic-database-url").unwrap();
    fs::set_permissions(&database, fs::Permissions::from_mode(0o400)).unwrap();
    unix_fs::chown(&database, Some(TEST_UID), Some(TEST_UID)).unwrap();
    let token = scratch.path("bridge-token");
    fs::write(&token, "manager-test-token\n").unwrap();
    fs::set_permissions(&token, fs::Permissions::from_mode(0o400)).unwrap();
    let runtime = PathBuf::from("/run/rentnerproxy");
    fs::create_dir(&runtime).unwrap();
    let _runtime = Scratch(runtime);
    let socket = Path::new(GATEWAY_SOCKET);
    let gateway_directory = socket.parent().unwrap();
    fs::create_dir(gateway_directory).unwrap();
    unix_fs::chown(gateway_directory, Some(WEB_UID), Some(WEB_UID)).unwrap();
    let mut authority = Command::new(env::current_exe().unwrap())
        .args(["--exact", "app_ipc::tests::lease_authority_fixture"])
        .env("RENTNERPROXY_TEST_LEASE_AUTHORITY", "1")
        .env_remove("LLVM_PROFILE_FILE")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .uid(WEB_UID)
        .gid(WEB_UID)
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    wait_for_fixture_path(socket).await;

    let launch = json!({
        "appId": "test.native", "installationId": "installation", "generation": 10,
        "uid": TEST_UID, "gid": TEST_UID, "executable": executable, "dataDirectory": data,
        "databaseUrlFile": database, "runtimeProfile": PROFILE,
        "appProtocol": ">=1.0.0 <2.0.0", "platformApi": ">=1.0.0 <1.0.1", "uiBridge": ">=1.0.0 <2.0.0",
    });
    let start = async |input: String| {
        let mut child = Command::new(&controller)
            .arg("--app-ipc")
            .env("RENTNERPROXY_CONTROLLER_TOKEN_FILE", &token)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut writer = child.stdin.take().unwrap();
        writer.write_all(input.as_bytes()).await.unwrap();
        (child, writer)
    };
    let send = async |input: String| {
        let (child, _writer) = start(input).await;
        // Hold the manager pipe until the child exits rather than revoking the launch.
        let output = timeout(Duration::from_secs(8), child.wait_with_output())
            .await
            .unwrap()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        String::from_utf8(output.stderr).unwrap()
    };
    assert!(
        send("{}\n".into())
            .await
            .contains("Invalid manager launch request")
    );
    assert!(
        send(format!("{launch}\nextra"))
            .await
            .contains("Invalid manager launch request")
    );
    let mut incompatible = launch.clone();
    incompatible["uiBridge"] = json!(">=1.2.0 <2.0.0");
    assert!(
        send(format!("{incompatible}\n"))
            .await
            .contains("Unsupported app runtime profile or protocol range")
    );
    let mut invalid_uid = launch.clone();
    invalid_uid["gid"] = json!(TEST_UID + 1);
    assert!(
        send(format!("{invalid_uid}\n"))
            .await
            .contains("Invalid app launch identity")
    );
    let linked = scratch.path("linked-data");
    unix_fs::symlink(&data, &linked).unwrap();
    let mut linked_launch = launch.clone();
    linked_launch["dataDirectory"] = json!(linked);
    assert!(
        linked_launch
            .as_object_mut()
            .unwrap()
            .remove("databaseUrlFile")
            .is_some()
    );
    assert!(
        send(format!("{linked_launch}\n"))
            .await
            .contains("Unsafe application runtime path or ownership")
    );
    fs::set_permissions(&token, fs::Permissions::from_mode(0o444)).unwrap();
    assert!(
        send(format!("{launch}\n"))
            .await
            .contains("Unsafe protected controller token file")
    );
    fs::set_permissions(&token, fs::Permissions::from_mode(0o400)).unwrap();

    assert!(
        send(format!("{launch}\n"))
            .await
            .contains("App generation has no live lease")
    );
    assert!(!data.join("descriptor.json").exists());

    let expired_config: LaunchConfig = serde_json::from_value(launch.clone()).unwrap();
    let (expired_sockets, _listener) =
        filesystem::GenerationSockets::bind(&scratch.path("expired-apps"), &expired_config)
            .unwrap();
    let fd = expired_sockets.lock.as_raw_fd();
    let mut expired = Command::new(&controller);
    expired
        .arg("--app-ipc-watchdog")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    // SAFETY: The fixture owns the live lock until the watchdog exits.
    unsafe {
        expired
            .as_std_mut()
            .pre_exec(move || filesystem::set_close_on_exec(fd, false));
    }
    let mut expired = expired.spawn().unwrap();
    let mut expired_pipe = expired.stdin.take().unwrap();
    let handoff = json!({
        "config": launch,
        "bootstrap": "synthetic-expired-bootstrap",
        "lock_fd": fd,
        "deadline": { "secs": 0, "nanos": 0 },
    });
    expired_pipe
        .write_all(format!("{handoff}\n").as_bytes())
        .await
        .unwrap();
    let expired_output = timeout(Duration::from_secs(5), expired.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(!expired_output.status.success());
    assert!(
        String::from_utf8(expired_output.stderr)
            .unwrap()
            .contains("(os error 110)")
    );
    assert!(!data.join("descriptor.json").exists());

    fs::write(gateway_directory.join("admitted"), []).unwrap();
    assert!(
        send(format!("{launch}\n"))
            .await
            .contains("Native app exited before readiness")
    );
    let descriptor: Value =
        serde_json::from_slice(&fs::read(data.join("descriptor.json")).unwrap()).unwrap();
    assert_eq!(descriptor["appId"], "test.native");
    assert_eq!(descriptor["generation"], 10);
    assert_eq!(descriptor["versions"]["uiBridge"], VERSION);
    let expected_socket = Path::new(APP_ROOT)
        .join(TEST_UID.to_string())
        .join("10/core.sock");
    assert_eq!(descriptor["coreSocket"].as_str(), expected_socket.to_str());
    assert!(!expected_socket.exists());

    fs::write(&executable, "#!/bin/sh\ncat >/dev/null\nsleep 20 &\nprintf '%s\\n' \"$!\" > descendant.tmp\nmv descendant.tmp descendant.pid\nwait\n").unwrap();
    let (mut broker, _writer) = start(format!("{launch}\n")).await;
    let marker = data.join("descendant.pid");
    wait_for_fixture_path(&marker).await;
    let descendant = fs::read_to_string(marker).unwrap();
    let descendant = descendant.trim().parse::<u32>().unwrap();
    let process = PathBuf::from(format!("/proc/{descendant}"));
    assert!(process.exists());
    let duplicate = send(format!("{launch}\n")).await;
    assert!(duplicate.contains("(os error 11)"), "{duplicate}");
    assert!(expected_socket.exists());

    let protected = scratch.path("outside-generation");
    fs::create_dir(&protected).unwrap();
    fs::write(protected.join("preserved"), []).unwrap();
    let abandoned = expected_socket.parent().unwrap();
    unix_fs::symlink(&protected, abandoned.join("app/untrusted-link")).unwrap();
    broker.kill().await.unwrap();
    timeout(Duration::from_secs(5), async {
        while process.exists() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the independent watchdog should kill and reap the descendant");
    assert!(
        expected_socket.exists(),
        "SIGKILL should exercise stale-path recovery"
    );
    fs::write(&executable, "#!/bin/sh\ncat > recovered.json\n").unwrap();
    let outcome = timeout(Duration::from_secs(6), async {
        loop {
            let outcome = send(format!("{launch}\n")).await;
            if !outcome.contains("(os error 11)") {
                return outcome;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        outcome.contains("Native app exited before readiness"),
        "{outcome}"
    );
    assert!(data.join("recovered.json").is_file());
    assert!(!abandoned.exists());
    assert!(protected.join("preserved").is_file());

    unix_fs::symlink(&protected, abandoned).unwrap();
    assert!(
        send(format!("{launch}\n"))
            .await
            .contains("Unsafe application runtime path or ownership")
    );
    assert!(protected.join("preserved").is_file());
    authority.kill().await.unwrap();
}

async fn wait_for_fixture_path(path: &Path) {
    timeout(Duration::from_secs(8), async {
        while !path.exists() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn lease_authority_fixture() {
    if env::var_os("RENTNERPROXY_TEST_LEASE_AUTHORITY").is_none() {
        return;
    }
    assert_eq!(uid(), WEB_UID);
    let listener = UnixListener::bind(GATEWAY_SOCKET).unwrap();
    loop {
        let (stream, _) = listener.accept().await.unwrap();
        let service = service_fn(|request| async {
            let mut reply = fixture_lease(request, Duration::from_secs(30), 10).await;
            if !Path::new(GATEWAY_SOCKET)
                .with_file_name("admitted")
                .is_file()
            {
                *reply.status_mut() = StatusCode::UNAUTHORIZED;
            }
            Ok::<_, Infallible>(reply)
        });
        server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn restricted_child_fixture() {
    if env::var_os("RENTNERPROXY_APP_BOOTSTRAP_FD").as_deref() != Some("0".as_ref()) {
        return;
    }
    use std::io::Read;
    let mut descriptor = String::new();
    io::stdin().read_to_string(&mut descriptor).unwrap();
    let descriptor: Value = serde_json::from_str(&descriptor).unwrap();
    assert_eq!(uid(), TEST_UID);
    assert_eq!(descriptor["appId"], "test.native");
    assert_eq!(descriptor["versions"]["appProtocol"], VERSION);
    assert_eq!(descriptor["versions"]["platformApi"], VERSION);
    assert_ne!(descriptor["appCredential"], descriptor["coreCredential"]);
    assert!(!descriptor["coreCredential"].as_str().unwrap().is_empty());
    assert_eq!(
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EPERM)
    );

    let core_socket = Path::new(descriptor["coreSocket"].as_str().unwrap());
    let lock = core_socket
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join(".9.lock");
    let app_fds = fs::read_dir("/proc/self/fd").unwrap();
    assert!(
        !app_fds
            .filter_map(|entry| fs::read_link(entry.unwrap().path()).ok())
            .any(|target| target == lock)
    );
    let mut core = open(core_socket).await;
    let credential = format!("Bearer {}", descriptor["coreCredential"].as_str().unwrap());
    let context = core
        .send_request(request(
            Method::GET,
            CONTEXT,
            &credential,
            "9",
            Bytes::new(),
        ))
        .await
        .unwrap();
    assert_eq!(context.status(), StatusCode::OK);
    let context: Value =
        serde_json::from_slice(&context.collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(context["context"], "verified");

    let listener = UnixListener::bind(descriptor["appSocket"].as_str().unwrap()).unwrap();
    let app_bearer = format!("Bearer {}", descriptor["appCredential"].as_str().unwrap());
    for _ in 0..2 {
        let (stream, _) = listener.accept().await.unwrap();
        assert_eq!(stream.peer_cred().unwrap().uid(), 0);
        server::conn::http1::Builder::new()
            .serve_connection(
                TokioIo::new(stream),
                service_fn(|request: Request<hyper::body::Incoming>| {
                    let app_bearer = &app_bearer;
                    async move {
                        assert_eq!(request.headers()["authorization"], app_bearer.as_str());
                        assert_eq!(request.headers()["x-app-installation"], "installation");
                        assert_eq!(request.headers()["x-app-generation"], "9");
                        let body = match request.uri().path() {
                            "/app/v1/health" => json!({"healthy": true}),
                            "/app/v1/ready" => {
                                fs::write("ready", []).unwrap();
                                json!({"ready": true, "protocolVersion": VERSION, "providers": []})
                            }
                            _ => panic!("Unexpected fixture RPC path"),
                        };
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(body.to_string()))))
                    }
                }),
            )
            .await
            .unwrap();
    }
    std::future::pending::<()>().await;
}
