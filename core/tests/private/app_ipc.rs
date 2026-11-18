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

const TOKEN: &str = "Bearer manager-test-token";
const CREDENTIAL: &str = "Bearer native-app-test-token";
const CONTEXT: &str = "/platform/v1/context";
const NOTIFY: &str = "/platform/v1/notifications";
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
        lease_seconds: 25,
        runtime_profile: PROFILE.into(),
        app_protocol: ">=1.0.0 <2.0.0".into(),
        platform_api: ">=1.0.0 <1.1.0".into(),
        ui_bridge: None,
    }
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
async fn privileged_generation_launches_restricted_child_and_revokes_listener() {
    if env::var_os("RENTNERPROXY_APP_BOOTSTRAP_FD").is_some() || uid() != 0 {
        return;
    }
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
    let backend = scratch.path("gateway.sock");
    let listener = UnixListener::bind(&backend).unwrap();
    let backend_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        assert_eq!(stream.peer_cred().unwrap().uid(), 0);
        let service = service_fn(|request: Request<hyper::body::Incoming>| async move {
            assert_eq!(request.uri(), CONTEXT);
            assert_eq!(request.headers()["authorization"], TOKEN);
            assert_eq!(
                request.headers()["x-rentnerproxy-app-uid"],
                TEST_UID.to_string()
            );
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                br#"{"context":"verified"}"#,
            ))))
        });
        server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .await
            .unwrap();
    });
    let (revoke, stopped) = oneshot::channel::<()>();
    let core = app_root.join(TEST_UID.to_string()).join("9/core.sock");
    let marker = data.join("ready");
    let mut task = tokio::spawn(async move {
        run_generation(
            config,
            &app_root,
            &backend,
            uid(),
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
    backend_task.await.unwrap();
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
