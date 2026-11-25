use std::cell::RefCell;

use tokio::task::JoinHandle;

use super::*;

const APP_AUTH: &str = "provider-dispatch-test-credential";
const AUTHORIZE: &str = "/internal/v1/app-generations/provider";
const MONITOR: &str = "/app/v1/providers/monitor-main";
const DNS: &str = "/app/v1/providers/dns-main";
const TEST_WAIT: Duration = Duration::from_secs(5);
const OBSERVED: &str = "2026-11-25T12:00:00.000Z";

fn monitor() -> Value {
    json!({"id": "monitor-main", "profile": "monitoring", "version": "1.0.0"})
}

fn dns() -> Value {
    json!({"id": "dns-main", "profile": "dns", "version": "1.0.0"})
}

/// A broker for a provider-only app: no UI bridge, two recorded registrations.
fn start_broker(scratch: &Scratch) -> (PathBuf, JoinHandle<io::Result<()>>) {
    let mut generation = test_generation(uid(), scratch.path("authority.sock"), uid());
    let state = Arc::get_mut(&mut generation).unwrap();
    state
        .set_app_target(scratch.path("app.sock"), APP_AUTH, false)
        .unwrap();
    let recorded = serde_json::from_value(json!([monitor(), dns()])).unwrap();
    assert!(state.providers.set(recorded).is_ok());
    let core = scratch.path("core.sock");
    let broker = tokio::spawn(gateway::serve(
        UnixListener::bind(&core).unwrap(),
        generation,
    ));
    (core, broker)
}

fn monitoring(limit: u64) -> Value {
    json!({"profile": "monitoring", "payload": {"limit": limit}})
}

fn dns_check(challenge: &str) -> Value {
    json!({"profile": "dns", "payload": {"action": "check", "challengeId": challenge}})
}

fn invocation(path: &str, body: &Value) -> Request<Full<Bytes>> {
    request(
        Method::POST,
        path,
        "Bearer manager-input",
        "9",
        Bytes::from(body.to_string()),
    )
}

fn samples(count: usize) -> Value {
    let samples: Vec<_> = (0..count)
        .map(|index| json!({"serviceId": format!("service-{index}"), "observedAt": OBSERVED, "healthy": true}))
        .collect();
    json!({"profile": "monitoring", "payload": {"samples": samples}})
}

fn json_reply(status: StatusCode, body: &Value) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}

fn empty_reply(status: StatusCode) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::new()))
        .unwrap()
}


fn verify_authority_request(parts: hyper::http::request::Parts, body: Bytes) {
    assert_eq!(parts.method, Method::POST);
    assert_eq!(parts.headers["authorization"], TOKEN);
    assert_eq!(parts.headers["content-type"], "application/json");
    let body: Value = serde_json::from_slice(&body).unwrap();
    let identity = json!({"appId": "test.native", "installationId": "installation",
        "generation": 9, "uid": uid()});
    assert_eq!(body["identity"], identity);
    match parts.uri.path() {
        AUTHORIZE => {
            assert_eq!(body.as_object().unwrap().len(), 2);
            assert!(matches!(
                body["providerId"].as_str(),
                Some("monitor-main" | "dns-main")
            ));
        }
        path => panic!("unexpected authority path {path}"),
    }
}

fn verify_app_request(parts: hyper::http::request::Parts, body: Bytes) {
    assert_eq!(parts.method, Method::POST);
    assert!(matches!(parts.uri.path(), MONITOR | DNS));
    assert_eq!(parts.headers["authorization"], format!("Bearer {APP_AUTH}"));
    assert_eq!(parts.headers["x-app-installation"], "installation");
    assert_eq!(parts.headers["x-app-generation"], "9");
    assert_eq!(parts.headers["content-type"], "application/json");
    assert_eq!(parts.headers["idempotency-key"], "request-one");
    for forbidden in ["cookie", "x-app-delegation", "x-rentnerproxy-app-id"] {
        assert!(!parts.headers.contains_key(forbidden));
    }
    let body: Value = serde_json::from_slice(&body).unwrap();
    let expected = if parts.uri.path() == MONITOR {
        monitoring(2)
    } else {
        dns_check("challenge-1")
    };
    assert_eq!(body, expected);
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
            let _ = server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        }
    })
}

async fn assert_provider_problem(
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

#[tokio::test]
async fn rejects_unregistered_and_invalid_invocations_before_contacting_peers() {
    if uid() != 0 {
        return;
    }
    let scratch = Scratch::create(&env::temp_dir());
    let authority = UnixListener::bind(scratch.path("authority.sock")).unwrap();
    let app = UnixListener::bind(scratch.path("app.sock")).unwrap();
    let (core, broker) = start_broker(&scratch);

    let mut missing_key = invocation(MONITOR, &monitoring(2));
    missing_key.headers_mut().remove("idempotency-key");
    let mut wrong_media_type = invocation(MONITOR, &monitoring(2));
    wrong_media_type
        .headers_mut()
        .insert("content-type", HeaderValue::from_static("text/plain"));
    let mut non_json = invocation(MONITOR, &monitoring(2));
    *non_json.body_mut() = Full::new(Bytes::from_static(b"incomplete JSON"));
    let mut wrong_generation = invocation(MONITOR, &monitoring(2));
    wrong_generation
        .headers_mut()
        .insert("x-app-generation", HeaderValue::from_static("8"));
    let mut wrong_installation = invocation(MONITOR, &monitoring(2));
    wrong_installation
        .headers_mut()
        .insert("x-app-installation", HeaderValue::from_static("other"));
    // A provider-only app has no UI bridge, so the broker never relays UI operations to it.
    let ui_operation = request(
        Method::POST,
        "/app/v1/api/greeting",
        "Bearer manager-input",
        "9",
        Bytes::from_static(br#"{"name":"demo"}"#),
    );

    for request in [
        invocation("/app/v1/providers/unknown", &monitoring(2)),
        invocation("/app/v1/providers/Not-A-Record", &monitoring(2)),
        ui_operation,
    ] {
        assert_provider_problem(&core, request, StatusCode::NOT_FOUND, "operationNotFound").await;
    }
    for request in [
        missing_key,
        non_json,
        // The contract bounds every request.
        invocation(MONITOR, &monitoring(0)),
        invocation(MONITOR, &json!({"profile": "monitoring", "payload": {}})),
        // The invocation must use the profile of the provider it addresses.
        invocation(MONITOR, &dns_check("challenge-1")),
        invocation(DNS, &monitoring(2)),
    ] {
        assert_provider_problem(&core, request, StatusCode::BAD_REQUEST, "invalidRequest").await;
    }
    assert_provider_problem(
        &core,
        wrong_media_type,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "unsupportedMediaType",
    )
    .await;
    for request in [wrong_generation, wrong_installation] {
        assert_provider_problem(
            &core,
            request,
            StatusCode::FORBIDDEN,
            "installationContextRejected",
        )
        .await;
    }
    for peer in [authority, app] {
        assert!(
            timeout(Duration::from_millis(10), peer.accept())
                .await
                .is_err(),
            "an invalid provider invocation reached a peer"
        );
    }
    broker.abort();
    assert!(broker.await.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn invokes_only_granted_providers_and_releases_only_matching_results() {
    if uid() != 0 {
        return;
    }
    let scratch = Scratch::create(&env::temp_dir());
    let (core, broker) = start_broker(&scratch);
    let granted = |registration: Value| json_reply(StatusCode::OK, &registration);
    let verified = json!({"profile": "dns", "payload": {"action": "check",
        "challengeId": "challenge-1", "outcome": "verified"}});
    let mut other_challenge = verified.clone();
    other_challenge["payload"]["challengeId"] = json!("challenge-2");
    let mut other_action = verified.clone();
    other_action["payload"]["action"] = json!("cleanup");

    let authority = serve_replies(
        &scratch.path("authority.sock"),
        vec![
            // Successful monitoring and DNS invocations, each authorized again before release.
            granted(monitor()),
            granted(monitor()),
            granted(dns()),
            granted(dns()),
            // Results for another resource, action or with too many items, and invalid ones.
            granted(dns()),
            granted(dns()),
            granted(monitor()),
            granted(monitor()),
            granted(monitor()),
            // An app conflict is released only while the provider is still authorized.
            granted(monitor()),
            granted(monitor()),
            granted(monitor()),
            // Authority decisions.
            empty_reply(StatusCode::NOT_FOUND),
            empty_reply(StatusCode::UNAUTHORIZED),
            granted(dns()),
            json_reply(StatusCode::OK, &json!({"id": "monitor-main"})),
            empty_reply(StatusCode::SERVICE_UNAVAILABLE),
            // A generation fenced or a grant revoked while the app answers withholds the result.
            granted(monitor()),
            empty_reply(StatusCode::UNAUTHORIZED),
            granted(monitor()),
            empty_reply(StatusCode::NOT_FOUND),
        ],
        verify_authority_request,
    );
    let app = serve_replies(
        &scratch.path("app.sock"),
        vec![
            json_reply(StatusCode::OK, &samples(2)),
            json_reply(StatusCode::OK, &verified),
            json_reply(StatusCode::OK, &other_challenge),
            json_reply(StatusCode::OK, &other_action),
            json_reply(StatusCode::OK, &samples(3)),
            json_reply(StatusCode::OK, &json!({"profile": "monitoring"})),
            json_reply(StatusCode::OK, &dns_check("challenge-1")),
            empty_reply(StatusCode::CONFLICT),
            empty_reply(StatusCode::INTERNAL_SERVER_ERROR),
            json_reply(StatusCode::OK, &samples(1)),
            json_reply(StatusCode::OK, &samples(1)),
        ],
        verify_app_request,
    );

    for (path, body, expected) in [
        (MONITOR, monitoring(2), samples(2)),
        (DNS, dns_check("challenge-1"), verified.clone()),
    ] {
        timeout(TEST_WAIT, async {
            let response = open(&core)
                .await
                .send_request(invocation(path, &body))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()["content-type"], "application/json");
            let result: Value =
                serde_json::from_slice(&response.collect().await.unwrap().to_bytes()).unwrap();
            assert_eq!(result, expected);
        })
        .await
        .unwrap();
    }
    for (path, body) in [
        (DNS, dns_check("challenge-1")),
        (DNS, dns_check("challenge-1")),
        (MONITOR, monitoring(2)),
        (MONITOR, monitoring(2)),
        (MONITOR, monitoring(2)),
    ] {
        assert_provider_problem(
            &core,
            invocation(path, &body),
            StatusCode::SERVICE_UNAVAILABLE,
            "platformUnavailable",
        )
        .await;
    }
    timeout(TEST_WAIT, async {
        let response = open(&core)
            .await
            .send_request(invocation(MONITOR, &monitoring(2)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(response.collect().await.unwrap().to_bytes().is_empty());
    })
    .await
    .unwrap();
    assert_provider_problem(
        &core,
        invocation(MONITOR, &monitoring(2)),
        StatusCode::SERVICE_UNAVAILABLE,
        "platformUnavailable",
    )
    .await;
    // Without a grant the provider does not exist for the platform; a fenced
    // generation is rejected; an unexpected or failed authority answer is unavailable.
    assert_provider_problem(
        &core,
        invocation(MONITOR, &monitoring(2)),
        StatusCode::NOT_FOUND,
        "operationNotFound",
    )
    .await;
    assert_provider_problem(
        &core,
        invocation(MONITOR, &monitoring(2)),
        StatusCode::FORBIDDEN,
        "installationContextRejected",
    )
    .await;
    for _ in 0..3 {
        assert_provider_problem(
            &core,
            invocation(MONITOR, &monitoring(2)),
            StatusCode::SERVICE_UNAVAILABLE,
            "platformUnavailable",
        )
        .await;
    }
    // The generation was fenced, then the grant was revoked, while the app answered.
    assert_provider_problem(
        &core,
        invocation(MONITOR, &monitoring(2)),
        StatusCode::FORBIDDEN,
        "installationContextRejected",
    )
    .await;
    assert_provider_problem(
        &core,
        invocation(MONITOR, &monitoring(2)),
        StatusCode::NOT_FOUND,
        "operationNotFound",
    )
    .await;
    timeout(TEST_WAIT, app).await.unwrap().unwrap();
    timeout(TEST_WAIT, authority).await.unwrap().unwrap();
    broker.abort();
    assert!(broker.await.unwrap_err().is_cancelled());
}
