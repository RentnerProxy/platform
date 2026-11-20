use std::cell::RefCell;

use hyper::Version;
use tokio::{task::JoinHandle, time};

use super::*;

const APP_API: &str = "/app/v1/api/greeting";
const APP_AUTH: &str = "ui-dispatch-test-credential";
const TEST_WAIT: Duration = Duration::from_secs(5);
const PAYLOAD: &[u8] = br#"{"name":"demo"}"#;
const REPLY: &[u8] = br#"{"greeting":"hello"}"#;

fn start_broker(scratch: &Scratch) -> (PathBuf, JoinHandle<io::Result<()>>) {
    let mut generation = test_generation(uid(), scratch.path("authority.sock"), uid());
    Arc::get_mut(&mut generation)
        .unwrap()
        .set_app_target(scratch.path("app.sock"), APP_AUTH)
        .unwrap();
    let core = scratch.path("core.sock");
    let broker = tokio::spawn(gateway::serve(
        UnixListener::bind(&core).unwrap(),
        generation,
    ));
    (core, broker)
}

fn ui_request() -> Request<Full<Bytes>> {
    request(
        Method::POST,
        APP_API,
        "Bearer manager-input",
        "9",
        Bytes::from_static(PAYLOAD),
    )
}

fn lease_request(body: Bytes) -> Request<Full<Bytes>> {
    request(Method::GET, gateway::UI_LEASE, TOKEN, "9", body)
}

async fn assert_ui_problem(
    core: &Path,
    request: Request<Full<Bytes>>,
    status: StatusCode,
    code: &str,
) {
    timeout(TEST_WAIT, async {
        assert_problem(&mut open(core).await, request, status, code).await;
    })
    .await
    .unwrap();
}

fn reply(status: StatusCode, content_type: Option<&str>, body: Bytes) -> Response<Full<Bytes>> {
    let mut reply = Response::builder().status(status);
    if let Some(content_type) = content_type {
        reply = reply.header("content-type", content_type);
    }
    reply.body(Full::new(body)).unwrap()
}

fn active_lease() -> Response<Full<Bytes>> {
    Response::new(Full::new(Bytes::from(
        lease_expiry(Duration::from_secs(60)).to_string(),
    )))
}

fn verify_authority_request(parts: hyper::http::request::Parts, body: Bytes) {
    assert_eq!(parts.method, Method::POST);
    assert_eq!(parts.uri, LEASE);
    assert_eq!(parts.headers["authorization"], TOKEN);
    assert_eq!(parts.headers["content-type"], "application/json");
    let identity: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        identity,
        json!({"identity": {"appId": "test.native", "installationId": "installation",
            "generation": 9, "uid": uid()}})
    );
}

fn verify_app_request(parts: hyper::http::request::Parts, body: Bytes) {
    assert_eq!(parts.method, Method::POST);
    assert_eq!(parts.uri, APP_API);
    assert_eq!(parts.headers["authorization"], format!("Bearer {APP_AUTH}"));
    assert_eq!(parts.headers["x-app-installation"], "installation");
    assert_eq!(parts.headers["x-app-generation"], "9");
    assert_eq!(parts.headers["content-type"], "application/json");
    assert_eq!(parts.headers["idempotency-key"], "request-one");
    for forbidden in ["cookie", "x-app-delegation", "x-rentnerproxy-app-id"] {
        assert!(!parts.headers.contains_key(forbidden));
    }
    assert_eq!(body, PAYLOAD);
}

fn serve_replies(
    socket: &Path,
    replies: Vec<Response<Full<Bytes>>>,
    verify: fn(hyper::http::request::Parts, Bytes),
) -> JoinHandle<()> {
    let listener = UnixListener::bind(socket).unwrap();
    tokio::spawn(async move {
        for reply in replies {
            let (stream, _) = listener.accept().await.unwrap();
            let reply = RefCell::new(Some(reply));
            let service = service_fn(move |request: Request<hyper::body::Incoming>| {
                let reply = reply.borrow_mut().take().unwrap();
                async move {
                    let (parts, body) = request.into_parts();
                    verify(parts, body.collect().await.unwrap().to_bytes());
                    Ok::<_, Infallible>(reply)
                }
            });
            // The broker may drop the connection once a response exceeds its body limit.
            let _ = server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        }
    })
}

#[tokio::test]
async fn rejects_invalid_ui_envelopes_before_contacting_peers() {
    if uid() != 0 {
        return;
    }
    let scratch = Scratch::create(&env::temp_dir());
    let authority = UnixListener::bind(scratch.path("authority.sock")).unwrap();
    let app = UnixListener::bind(scratch.path("app.sock")).unwrap();
    let (core, broker) = start_broker(&scratch);
    let mut unsupported_version = ui_request();
    *unsupported_version.version_mut() = Version::HTTP_10;
    let mut absolute_uri = ui_request();
    *absolute_uri.uri_mut() = "http://localhost/app/v1/api/greeting".parse().unwrap();
    let mut query = ui_request();
    *query.uri_mut() = "/app/v1/api/greeting?name=demo".parse().unwrap();
    let mut missing_installation = ui_request();
    missing_installation
        .headers_mut()
        .remove("x-app-installation");
    let mut wrong_method = ui_request();
    *wrong_method.method_mut() = Method::GET;
    let mut wrong_path = ui_request();
    *wrong_path.uri_mut() = "/app/v1/api/greeting/details".parse().unwrap();
    let mut missing_key = ui_request();
    missing_key.headers_mut().remove("idempotency-key");
    let mut invalid_key = ui_request();
    invalid_key
        .headers_mut()
        .insert("idempotency-key", HeaderValue::from_static("two words"));
    let mut repeated_generation = ui_request();
    repeated_generation
        .headers_mut()
        .append("x-app-generation", HeaderValue::from_static("9"));
    let mut wrong_media_type = ui_request();
    wrong_media_type
        .headers_mut()
        .insert("content-type", HeaderValue::from_static("text/plain"));
    let mut non_json = ui_request();
    *non_json.body_mut() = Full::new(Bytes::from_static(b"incomplete JSON"));
    let mut oversized = ui_request();
    *oversized.body_mut() = Full::new(Bytes::from(vec![b' '; gateway::MAX_JSON_BYTES + 1]));

    for request in [
        unsupported_version,
        absolute_uri,
        query,
        missing_installation,
    ] {
        assert_ui_problem(
            &core,
            request,
            StatusCode::FORBIDDEN,
            "installationContextRejected",
        )
        .await;
    }
    for request in [wrong_method, wrong_path] {
        assert_ui_problem(&core, request, StatusCode::NOT_FOUND, "operationNotFound").await;
    }
    for request in [
        missing_key,
        invalid_key,
        repeated_generation,
        non_json,
        lease_request(Bytes::from_static(b"unexpected")),
    ] {
        assert_ui_problem(&core, request, StatusCode::BAD_REQUEST, "invalidRequest").await;
    }
    assert_ui_problem(
        &core,
        wrong_media_type,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "unsupportedMediaType",
    )
    .await;
    assert_ui_problem(
        &core,
        oversized,
        StatusCode::PAYLOAD_TOO_LARGE,
        "payloadTooLarge",
    )
    .await;
    for peer in [authority, app] {
        assert!(
            timeout(Duration::from_millis(10), peer.accept())
                .await
                .is_err(),
            "invalid UI request reached a peer"
        );
    }
    broker.abort();
    assert!(broker.await.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn checks_ui_lease_without_dispatching_to_app() {
    if uid() != 0 {
        return;
    }
    let scratch = Scratch::create(&env::temp_dir());
    let (core, broker) = start_broker(&scratch);
    let authority = serve_replies(
        &scratch.path("authority.sock"),
        vec![
            active_lease(),
            reply(
                StatusCode::OK,
                None,
                Bytes::from_static(br#"{"expiresAt":0}"#),
            ),
            reply(
                StatusCode::OK,
                None,
                Bytes::from_static(b"invalid lease reply"),
            ),
            reply(StatusCode::SERVICE_UNAVAILABLE, None, Bytes::new()),
        ],
        verify_authority_request,
    );

    timeout(TEST_WAIT, async {
        let response = open(&core)
            .await
            .send_request(lease_request(Bytes::new()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(response.collect().await.unwrap().to_bytes().is_empty());
    })
    .await
    .unwrap();
    assert_ui_problem(
        &core,
        lease_request(Bytes::new()),
        StatusCode::FORBIDDEN,
        "installationContextRejected",
    )
    .await;
    for _ in 0..2 {
        assert_ui_problem(
            &core,
            lease_request(Bytes::new()),
            StatusCode::SERVICE_UNAVAILABLE,
            "platformUnavailable",
        )
        .await;
    }
    timeout(TEST_WAIT, authority).await.unwrap().unwrap();
    broker.abort();
    assert!(broker.await.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn checks_app_replies_and_the_lease_before_releasing_ui_data() {
    if uid() != 0 {
        return;
    }
    let scratch = Scratch::create(&env::temp_dir());
    let (core, broker) = start_broker(&scratch);
    let valid = || {
        reply(
            StatusCode::OK,
            Some(" Application/JSON; charset=utf-8"),
            Bytes::from_static(REPLY),
        )
    };
    let conflict = || {
        reply(
            StatusCode::CONFLICT,
            None,
            Bytes::from_static(b"app detail"),
        )
    };
    let mut duplicated_media_type = valid();
    duplicated_media_type
        .headers_mut()
        .append("content-type", HeaderValue::from_static("application/json"));
    let mut success = valid();
    success
        .headers_mut()
        .insert("set-cookie", HeaderValue::from_static("app-only=test"));
    let app = serve_replies(
        &scratch.path("app.sock"),
        vec![
            conflict(),
            reply(
                StatusCode::BAD_GATEWAY,
                Some("application/json"),
                Bytes::from_static(REPLY),
            ),
            reply(StatusCode::OK, None, Bytes::from_static(REPLY)),
            reply(
                StatusCode::OK,
                Some("text/plain"),
                Bytes::from_static(REPLY),
            ),
            duplicated_media_type,
            reply(
                StatusCode::OK,
                Some("application/json"),
                Bytes::from_static(b"invalid app JSON"),
            ),
            reply(
                StatusCode::OK,
                Some("application/json"),
                Bytes::from(vec![b' '; gateway::MAX_JSON_BYTES + 1]),
            ),
            success,
            valid(),
            conflict(),
        ],
        verify_app_request,
    );
    // Check before each dispatch and after the live conflict and successful reply.
    let mut leases: Vec<_> = (0..10).map(|_| active_lease()).collect();
    // Revoke after the next successful reply and after the next conflict.
    for _ in 0..2 {
        leases.extend([
            active_lease(),
            reply(StatusCode::UNAUTHORIZED, None, Bytes::new()),
        ]);
    }
    // The final dispatch has a valid lease but the app socket is closed.
    leases.push(active_lease());
    let authority = serve_replies(
        &scratch.path("authority.sock"),
        leases,
        verify_authority_request,
    );
    timeout(TEST_WAIT, async {
        let response = open(&core).await.send_request(ui_request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(response.collect().await.unwrap().to_bytes().is_empty());
    })
    .await
    .unwrap();
    for _ in 0..6 {
        assert_ui_problem(
            &core,
            ui_request(),
            StatusCode::SERVICE_UNAVAILABLE,
            "platformUnavailable",
        )
        .await;
    }
    timeout(TEST_WAIT, async {
        let response = open(&core).await.send_request(ui_request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "application/json");
        assert!(!response.headers().contains_key("set-cookie"));
        assert_eq!(response.collect().await.unwrap().to_bytes(), REPLY);
    })
    .await
    .unwrap();
    for _ in 0..2 {
        assert_ui_problem(
            &core,
            ui_request(),
            StatusCode::FORBIDDEN,
            "installationContextRejected",
        )
        .await;
    }
    timeout(TEST_WAIT, app).await.unwrap().unwrap();
    assert_ui_problem(
        &core,
        ui_request(),
        StatusCode::SERVICE_UNAVAILABLE,
        "platformUnavailable",
    )
    .await;
    timeout(TEST_WAIT, authority).await.unwrap().unwrap();
    broker.abort();
    assert!(broker.await.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn closes_a_waiting_app_connection_at_the_ui_deadline() {
    if uid() != 0 {
        return;
    }
    let scratch = Scratch::create(&env::temp_dir());
    let (core, broker) = start_broker(&scratch);
    let authority = serve_replies(
        &scratch.path("authority.sock"),
        vec![active_lease()],
        verify_authority_request,
    );
    let app = UnixListener::bind(scratch.path("app.sock")).unwrap();
    let (waiting, app_waiting) = oneshot::channel();
    let app = tokio::spawn(async move {
        let (stream, _) = app.accept().await.unwrap();
        let waiting = RefCell::new(Some(waiting));
        let service = service_fn(move |request: Request<hyper::body::Incoming>| {
            let waiting = waiting.borrow_mut().take().unwrap();
            async move {
                let (parts, body) = request.into_parts();
                verify_app_request(parts, body.collect().await.unwrap().to_bytes());
                waiting.send(()).unwrap();
                std::future::pending::<Result<Response<Full<Bytes>>, Infallible>>().await
            }
        });
        let _ = server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .await;
    });
    let manager = tokio::spawn(async move {
        let mut sender = open(&core).await;
        assert_problem(
            &mut sender,
            ui_request(),
            StatusCode::GATEWAY_TIMEOUT,
            "deadlineExceeded",
        )
        .await;
        sender
    });

    timeout(TEST_WAIT, app_waiting).await.unwrap().unwrap();
    time::pause();
    time::advance(gateway::RPC_TIMEOUT).await;
    time::resume();
    let manager = timeout(TEST_WAIT, manager).await.unwrap().unwrap();
    for task in [app, authority] {
        timeout(TEST_WAIT, task).await.unwrap().unwrap();
    }
    assert!(
        !manager.is_closed(),
        "manager connection closed before the app"
    );
    drop(manager);
    broker.abort();
    assert!(broker.await.unwrap_err().is_cancelled());
}
