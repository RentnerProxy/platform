use super::*;

use crate::app_install::StagedPackage;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::json as value;
use std::{
    process::Stdio,
    sync::atomic::{AtomicBool, Ordering},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    process::Command,
    sync::Notify,
    task::JoinHandle,
};

const FIXTURE_SOCKET: &str = "RENTNERPROXY_TEST_APP_UI_SOCKET";
const FIXTURE_REPLY: &str = "APP_UI_HTTP ";
const INSTALLATION: &str = "/v1/apps/demo/1";
const OPERATION: &str = "/v1/apps/demo/1/operations/greeting";
const REQUEST_BODY: &[u8] = br#"{"resourceId":"fixture","name":"Kevin"}"#;

pub(in crate::app_manager) async fn manager_catalog(
    action: Option<&Value>,
    expected_status: u16,
) -> Value {
    let client = Client(PathBuf::from(SOCKET));
    let reply = match action {
        Some(action) => {
            client
                .request(
                    "POST",
                    "/v1/catalog/lifecycle",
                    "Content-Type: application/json\r\n",
                    &serde_json::to_vec(action).unwrap(),
                )
                .await
        }
        None => client.get("/v1/catalog").await,
    };
    reply.assert(expected_status);
    if expected_status < 300 {
        reply.json()
    } else {
        Value::Null
    }
}

#[test]
fn generation_path_identity_and_payload_are_unambiguous() {
    assert_eq!(generation_number("1"), Some(1));
    assert_eq!(generation_number("9007199254740991"), Some(MAX_GENERATION));
    for number in ["", "0", "01", "+1", "1.0", "9007199254740992", "%31"] {
        assert_eq!(generation_number(number), None);
    }
    assert!(json_object(br#"{"field":["value"]}"#).is_some());
    assert!(json_object(br#"{"field":1,"field":2}"#).is_none());
    assert!(json_object(br#"["value"]"#).is_none());
    let one_hundred = vec![0; 100];
    let too_many = vec![0; 101];
    assert!(bounded_lists(&serde_json::json!({"list":one_hundred})));
    assert!(!bounded_lists(&serde_json::json!({"list":too_many})));
}

#[tokio::test]
async fn generation_replacement_and_drain_revoke_open_entries() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let temp = tempfile::tempdir_in("/run").unwrap();
    fs::create_dir(temp.path().join("ui")).unwrap();
    fs::write(temp.path().join("ui/index.html"), b"hello").unwrap();
    let staged = StagedPackage {
        directory: temp.path().to_path_buf(),
        manifest: value!({
            "id": "fixture.test", "display": {"name": "Fixture"},
            "ui": {"entrypoint": "ui/index.html", "slots": []},
            "permissions": [], "capabilities": [],
        }),
        archive_sha256: "0".repeat(64),
        manifest_sha256: "1".repeat(64),
        catalog_revision: 1,
    };
    let registry = Registry::default();
    let publish = |generation| {
        let package = Package::load(&staged, "demo".to_owned(), generation, 20_000)
            .unwrap()
            .unwrap();
        registry.publish(package).unwrap()
    };
    let first = publish(1);
    let open = registry.entry("demo", 1).unwrap();
    assert_eq!(open.package.asset("index.html").unwrap(), b"hello");
    let (selected, resource, value) = selection(&registry, "/v1/apps/demo/1/metadata").unwrap();
    assert!(Arc::ptr_eq(&open, &selected));
    assert_eq!((resource, value), ("metadata", None));
    let second = publish(2);
    assert_eq!(
        registry.entry("demo", 1).err(),
        Some(StatusCode::PRECONDITION_FAILED)
    );
    assert_eq!(
        protected(&open, async { Ok(()) }).await,
        Err(StatusCode::PRECONDITION_FAILED)
    );
    drop(first);
    assert!(registry.entry("demo", 2).is_ok());
    drop(second);
    assert_eq!(registry.entry("demo", 2).err(), Some(StatusCode::NOT_FOUND));
}

#[tokio::test]
async fn closing_a_generation_withdraws_its_provider_endpoint() {
    let temp = tempfile::tempdir().unwrap();
    let registry = Registry::default();
    let child = Command::new("sleep")
        .arg("30")
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut live = super::super::runtime::Running::fixture_child(child);
    live.providers = registry
        .providers
        .publish_in("closing", 20_005, 1, temp.path());
    let key = HeaderValue::from_static("closing-key");
    let invoke = || {
        registry
            .providers
            .invoke("closing", "monitor-main", &key, Bytes::new())
    };
    // While published, the call reaches the (absent) broker instead of a missing endpoint.
    assert_ne!(invoke().await.err(), Some(StatusCode::NOT_FOUND));
    // A stop closes the generation before waiting for its child to exit.
    live.close();
    assert_eq!(invoke().await.err(), Some(StatusCode::NOT_FOUND));
}

#[test]
fn local_http_encoders_enforce_their_bounds() {
    struct EncodeFailure;
    impl Serialize for EncodeFailure {
        fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("fixture encoding failure"))
        }
    }
    assert_eq!(
        json(&EncodeFailure, 32).err(),
        Some(StatusCode::SERVICE_UNAVAILABLE)
    );
    assert_eq!(
        json(&["large"], 1).err(),
        Some(StatusCode::SERVICE_UNAVAILABLE)
    );
    assert_eq!(
        response("invalid\nmedia", Bytes::new()).err(),
        Some(StatusCode::SERVICE_UNAVAILABLE)
    );
    assert_eq!(
        socket_status(io::Error::from(io::ErrorKind::PermissionDenied)),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[test]
#[ignore = "subprocess for the isolated app UI fixture"]
fn web_peer_fixture() {
    use std::io::{Read, Write};

    assert_eq!(unsafe { libc::geteuid() }, WEB_UID);
    let path = std::env::var_os(FIXTURE_SOCKET).expect("UI socket fixture path");
    let mut request = Vec::new();
    std::io::stdin().read_to_end(&mut request).unwrap();
    let mut socket = std::os::unix::net::UnixStream::connect(path).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(14)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(14)))
        .unwrap();
    // The manager can reject a size limit and close while the request is still writing.
    if let Err(error) = socket.write_all(&request) {
        assert!(matches!(
            error.kind(),
            io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
        ));
    }
    let mut response = Vec::new();
    if let Err(error) = socket.read_to_end(&mut response) {
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        assert!(!response.is_empty());
    }
    println!("{FIXTURE_REPLY}{}", STANDARD.encode(response));
}

#[derive(Clone)]
struct Client(PathBuf);

struct HttpReply {
    status: u16,
    headers: String,
    body: Vec<u8>,
}

impl HttpReply {
    fn assert(&self, status: u16) {
        assert_eq!(self.status, status, "{}", self.headers);
        assert!(
            self.headers
                .lines()
                .filter_map(|line| line.split_once(':'))
                .filter(|(name, _)| name.eq_ignore_ascii_case("cache-control"))
                .flat_map(|(_, value)| value.split(','))
                .any(|directive| directive.trim().eq_ignore_ascii_case("no-store")),
            "{}",
            self.headers
        );
    }

    fn json(&self) -> Value {
        assert!(self.headers.contains("content-type: application/json"));
        serde_json::from_slice(&self.body).unwrap()
    }
}

impl Client {
    async fn raw(&self, request: Vec<u8>) -> HttpReply {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .uid(WEB_UID)
            .gid(WEB_UID)
            .args([
                "--ignored",
                "--exact",
                "app_manager::ui::tests::web_peer_fixture",
                "--nocapture",
            ])
            .env(FIXTURE_SOCKET, &self.0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        let output = timeout(Duration::from_secs(16), async {
            input.write_all(&request).await.unwrap();
            drop(input);
            child.wait_with_output().await.unwrap()
        })
        .await
        .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8(output.stdout).unwrap();
        let encoded = text
            .lines()
            .find_map(|line| line.split_once(FIXTURE_REPLY))
            .map(|(_, encoded)| encoded)
            .unwrap();
        let bytes = STANDARD.decode(encoded).unwrap();
        let header_end = bytes
            .windows(4)
            .position(|part| part == b"\r\n\r\n")
            .unwrap();
        let headers = String::from_utf8_lossy(&bytes[..header_end]).to_ascii_lowercase();
        let status = headers
            .split_ascii_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        HttpReply {
            status,
            headers,
            body: bytes[header_end + 4..].to_vec(),
        }
    }

    async fn request(&self, method: &str, path: &str, headers: &str, body: &[u8]) -> HttpReply {
        let mut request = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n{headers}Content-Length: {}\r\n\r\n",
            body.len(),
        ).into_bytes();
        request.extend_from_slice(body);
        self.raw(request).await
    }

    async fn get(&self, path: &str) -> HttpReply {
        self.request("GET", path, "", b"").await
    }

    async fn post(&self, body: &[u8]) -> HttpReply {
        self.request(
            "POST",
            OPERATION,
            "Content-Type: Application/JSON; charset=utf-8\r\nIdempotency-Key: caller-7\r\n",
            body,
        )
        .await
    }
}

pub(in crate::app_manager) async fn fixture_request(
    method: &str,
    path: &str,
    headers: &str,
    body: &[u8],
) -> (u16, Value) {
    let client = Client(PathBuf::from(SOCKET));
    let reply = client.request(method, path, headers, body).await;
    let value = if reply.body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&reply.body).unwrap()
    };
    (reply.status, value)
}

/// GET a UI asset over the manager's web socket and return its status and raw body.
pub(in crate::app_manager) async fn fixture_asset(path: &str) -> (u16, Vec<u8>) {
    let reply = Client(PathBuf::from(SOCKET)).get(path).await;
    (reply.status, reply.body)
}

fn staged_package(root: &Path) -> StagedPackage {
    fs::create_dir(root.join("ui")).unwrap();
    fs::create_dir(root.join("api")).unwrap();
    fs::write(root.join("ui/index.html"), b"<h1>Fixture</h1>").unwrap();
    fs::File::create(root.join("ui/large.bin"))
        .unwrap()
        .set_len(8 * 1024 * 1024 + 1)
        .unwrap();
    let api = value!({
        "openapi": "3.1.0",
        "x-rentnerproxy-ui": {"routes": ["details"], "dialogs": ["confirm"], "events": ["updated"]},
        "paths": {"/app/v1/api/greeting": {"post": {
            "operationId": "greeting",
            "x-rentnerproxy-access": {
                "permissionKey": "greet",
                "resource": {
                    "capability": {"id": "proxy.hosts.read.v1", "scope": "proxyHosts"},
                    "resourceIdField": "resourceId",
                },
            },
            "requestBody": {"content": {"application/json": {"schema": {
                "type": "object",
                "properties": {"resourceId": {"type": "string"}, "name": {"type": "string"}},
                "required": ["resourceId", "name"], "additionalProperties": false,
            }}}},
            "responses": {"200": {"content": {"application/json": {"schema": {
                "type": "object", "properties": {"greeting": {"type": "string"}},
                "required": ["greeting"], "additionalProperties": false,
            }}}}},
        }}},
    });
    fs::write(
        root.join("api/openapi.json"),
        serde_json::to_vec(&api).unwrap(),
    )
    .unwrap();
    StagedPackage {
        directory: root.to_path_buf(),
        manifest: value!({
            "id": "fixture.test", "display": {"name": "Fixture"}, "api": "api/openapi.json",
            "ui": {"entrypoint": "ui/index.html", "slots": ["navigation"]},
            "permissions": ["greet"],
            "capabilities": [{"id": "proxy.hosts.read.v1", "scope": "proxyHosts"}],
        }),
        archive_sha256: "0".repeat(64),
        manifest_sha256: "1".repeat(64),
        catalog_revision: 1,
    }
}

#[derive(Clone)]
struct BrokerReply {
    status: StatusCode,
    media: &'static str,
    body: Bytes,
}

impl BrokerReply {
    fn success() -> Self {
        Self {
            status: StatusCode::OK,
            media: "application/json",
            body: Bytes::from_static(br#"{"greeting":"Gude Kevin"}"#),
        }
    }
}

struct Broker {
    lease: Mutex<StatusCode>,
    reply: Mutex<BrokerReply>,
    hold_calls: AtomicBool,
    entered: Notify,
    release: Notify,
}

struct Task(JoinHandle<()>);

impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl Broker {
    fn bind(publication: &Publication) -> (Arc<Self>, Task) {
        let path = &publication.entry.broker_socket;
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(path).unwrap();
        let installation = publication.entry.package.metadata.installation_id.clone();
        let generation = publication.entry.package.metadata.generation.to_string();
        let broker = Arc::new(Self {
            lease: Mutex::new(StatusCode::NO_CONTENT),
            reply: Mutex::new(BrokerReply::success()),
            hold_calls: AtomicBool::new(false),
            entered: Notify::new(),
            release: Notify::new(),
        });
        let behavior = Arc::clone(&broker);
        let task = Task(tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    _ = connections.join_next(), if !connections.is_empty() => {},
                    accepted = listener.accept() => {
                        let (stream, _) = accepted.unwrap();
                        assert_eq!(stream.peer_cred().unwrap().uid(), 0);
                        let behavior = Arc::clone(&behavior);
                        let installation = installation.clone();
                        let generation = generation.clone();
                        connections.spawn(async move {
                            let service = service_fn(move |request: Request<Incoming>| {
                                assert_eq!(request.headers()["x-app-installation"], installation);
                                assert_eq!(request.headers()["x-app-generation"], generation);
                                assert_eq!(request.headers()[header::HOST], "localhost");
                                let behavior = Arc::clone(&behavior);
                                async move {
                                    let response = behavior.respond(request).await;
                                    Ok::<_, std::convert::Infallible>(response)
                                }
                            });
                            let _ = http1::Builder::new().keep_alive(false)
                                .serve_connection(TokioIo::new(stream), service).await;
                        });
                    }
                }
            }
        }));
        (broker, task)
    }

    async fn respond(&self, request: Request<Incoming>) -> Response<Full<Bytes>> {
        if request.uri().path() == UI_LEASE {
            assert_eq!(request.method(), Method::GET);
            return Response::builder()
                .status(*self.lease.lock().unwrap())
                .body(Full::new(Bytes::new()))
                .unwrap();
        }
        assert_eq!(request.uri().path(), "/app/v1/api/greeting");
        assert_eq!(request.method(), Method::POST);
        assert_eq!(request.headers()["idempotency-key"], "caller-7");
        assert_eq!(request.headers()[header::CONTENT_TYPE], "application/json");
        assert!(!request.headers().contains_key(header::AUTHORIZATION));
        assert!(!request.headers().contains_key(header::COOKIE));
        assert_eq!(
            request
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .as_ref(),
            REQUEST_BODY,
        );
        if self.hold_calls.load(Ordering::Acquire) {
            self.entered.notify_one();
            self.release.notified().await;
        }
        let reply = self.reply.lock().unwrap().clone();
        Response::builder()
            .status(reply.status)
            .header(header::CONTENT_TYPE, reply.media)
            .body(Full::new(reply.body))
            .unwrap()
    }
}

#[tokio::test]
#[ignore = "requires the isolated root runner and an independent web peer UID"]
async fn privileged_web_socket_serves_generation_scoped_ui() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let scratch = tempfile::tempdir_in("/run").unwrap();
    fs::set_permissions(scratch.path(), Permissions::from_mode(0o711)).unwrap();
    let path = scratch.path().join("web/web.sock");
    assert!(bind_path(&scratch.path().join("absent/web/web.sock")).is_err());
    let initial = bind_path(&path).unwrap();
    let metadata = fs::symlink_metadata(&path).unwrap();
    assert_eq!(
        (metadata.uid(), metadata.gid(), metadata.mode() & 0o7777),
        (0, WEB_UID, 0o660)
    );
    drop(initial);
    drop(bind_path(&path).unwrap());
    fs::remove_file(&path).unwrap();
    fs::write(&path, "unexpected file").unwrap();
    assert!(bind_path(&path).is_err());
    assert_eq!(fs::read_to_string(&path).unwrap(), "unexpected file");
    fs::remove_file(&path).unwrap();
    let parent = path.parent().unwrap();
    fs::set_permissions(parent, Permissions::from_mode(0o711)).unwrap();
    assert!(bind_path(&path).is_err());
    fs::set_permissions(parent, Permissions::from_mode(0o710)).unwrap();
    let listener = bind_path(&path).unwrap();
    let registry = Registry::default();
    let service = registry.clone();
    let (endpoint, mut requests, release) = catalog::tests::ready_endpoint();
    let _server = Task(tokio::spawn(async move {
        serve(listener, service, endpoint).await.unwrap()
    }));
    let client = Client(path);

    let mut outsider = UnixStream::connect(&client.0).await.unwrap();
    let _ = outsider
        .write_all(b"GET /v1/apps HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await;
    let mut unexpected_response = Vec::new();
    let _ = timeout(
        Duration::from_secs(2),
        outsider.read_to_end(&mut unexpected_response),
    )
    .await
    .unwrap();
    assert!(unexpected_response.is_empty());

    let initial = client.get("/v1/apps").await;
    initial.assert(200);
    assert_eq!(initial.json(), value!([]));
    assert_catalog_requests(&client, &mut requests, release).await;
    let staged = staged_package(scratch.path());
    let app_root = scratch.path().join("apps");
    let publish = |id: &str, generation, uid| {
        let package = Package::load(&staged, id.to_owned(), generation, uid)
            .unwrap()
            .unwrap();
        registry.publish_in(package, &app_root).unwrap()
    };
    let demo = publish("demo", 1, 20_001);
    let (broker, _backend) = Broker::bind(&demo);
    let another = publish("another", 2, 20_002);
    let (_second_broker, _second_backend) = Broker::bind(&another);
    let offline = publish("offline", 1, 20_003);

    assert_metadata_and_assets(&client).await;
    assert_invalid_requests(&client).await;
    assert_invocation(&client, &demo, &broker).await;
    assert_provider_invocations(&client, &registry, &app_root).await;

    let broker_path = &offline.entry.broker_socket;
    fs::create_dir_all(broker_path.parent().unwrap()).unwrap();
    fs::write(broker_path, "not a broker").unwrap();
    client.get("/v1/apps/offline/1/metadata").await.assert(503);
    *broker.lease.lock().unwrap() = StatusCode::INTERNAL_SERVER_ERROR;
    client
        .get(&format!("{INSTALLATION}/metadata"))
        .await
        .assert(503);
    *broker.lease.lock().unwrap() = StatusCode::FORBIDDEN;
    client
        .get(&format!("{INSTALLATION}/metadata"))
        .await
        .assert(412);
    let listing = client.get("/v1/apps").await;
    listing.assert(200);
    assert_eq!(listing.json().as_array().unwrap().len(), 1);
    assert_eq!(listing.json()[0]["installationId"], "another");
    *broker.lease.lock().unwrap() = StatusCode::NO_CONTENT;

    broker.hold_calls.store(true, Ordering::Release);
    let inflight = tokio::spawn({
        let client = client.clone();
        async move { client.post(REQUEST_BODY).await }
    });
    timeout(Duration::from_secs(3), broker.entered.notified())
        .await
        .unwrap();
    drop(demo);
    inflight.await.unwrap().assert(412);
    broker.release.notify_one();
    client
        .get(&format!("{INSTALLATION}/metadata"))
        .await
        .assert(404);
}

async fn assert_catalog_requests(
    client: &Client,
    requests: &mut tokio::sync::mpsc::Receiver<catalog::Request>,
    release: catalog::Selection,
) {
    const INSTALL: &str = "/v1/catalog/install";
    const JSON: &str = "Content-Type: application/json\r\n";
    let initial = client.get("/v1/catalog").await;
    initial.assert(200);
    assert_eq!(initial.json()["state"], "ready");
    assert_eq!(initial.json()["installations"], value!([]));
    assert_eq!(initial.json()["lifecycle"], value!(null));
    assert_eq!(
        initial.json()["entries"][0]["appId"],
        "rentnerproxy.greeting"
    );
    client.request("POST", INSTALL, "", b"{}").await.assert(400);
    client
        .request("POST", INSTALL, JSON, b"{")
        .await
        .assert(400);
    client
        .request(
            "POST",
            INSTALL,
            JSON,
            &[b' '; MAX_CATALOG_REQUEST_BYTES + 1],
        )
        .await
        .assert(413);
    // An approval of up to 128 grants fits. A malformed approval is refused before admission.
    let mut malformed = serde_json::to_value(&release).unwrap();
    malformed["approval"] = value!([{"capability": {"id": "app.audit.record"}}]);
    let malformed = serde_json::to_vec(&malformed).unwrap();
    client
        .request("POST", INSTALL, JSON, &malformed)
        .await
        .assert(400);
    let target = "/v1/catalog/target-check";
    client.request("POST", target, "", b"{}").await.assert(400);
    client.request("POST", target, JSON, b"{").await.assert(400);
    client
        .request("POST", target, JSON, &[b' '; MAX_INSTALL_BYTES + 1])
        .await
        .assert(413);
    let mut environment = value!({
        "runtimeProfile": "rentnerproxy-linux-v1", "platformApi": "1.1.0",
        "appProtocol": "1.0.0", "uiBridge": null, "engineCapabilities": [],
    });
    environment["engineCapabilities"] = value!(["Caddy.crowdsec.v1"]);
    client
        .request(
            "POST",
            target,
            JSON,
            &serde_json::to_vec(&environment).unwrap(),
        )
        .await
        .assert(400);
    environment["engineCapabilities"] = value!([]);
    // The fixture endpoint has no installer configuration, so no accepted catalog can answer.
    client
        .request(
            "POST",
            target,
            JSON,
            &serde_json::to_vec(&environment).unwrap(),
        )
        .await
        .assert(503);
    let lifecycle = "/v1/catalog/lifecycle";
    client
        .request("POST", lifecycle, JSON, b"{}")
        .await
        .assert(400);
    let lifecycle_body = serde_json::to_vec(&value!({
        "action": "purge",
        "installationId": "demo",
        "expected": { "generation": 1, "version": "1.0.0", "archiveSha256": "a".repeat(64) }
    }))
    .unwrap();
    client
        .request("POST", lifecycle, JSON, &lifecycle_body)
        .await
        .assert(409);

    let mut wrong = serde_json::to_value(&release).unwrap();
    wrong["archiveSha256"] = value!("f".repeat(64));
    client
        .request("POST", INSTALL, JSON, &serde_json::to_vec(&wrong).unwrap())
        .await
        .assert(409);

    let selected = serde_json::to_vec(&release).unwrap();
    for _ in 0..2 {
        let accepted = client.request("POST", INSTALL, JSON, &selected).await;
        accepted.assert(202);
        assert_eq!(accepted.json()["status"], "installing");
    }
    assert_eq!(
        requests.try_recv().unwrap(),
        catalog::Request::Install(release)
    );
    assert!(requests.try_recv().is_err());
    let pending = client.get("/v1/catalog").await;
    pending.assert(200);
    assert_eq!(pending.json()["install"]["status"], "installing");
}

async fn assert_metadata_and_assets(client: &Client) {
    let list = client.get("/v1/apps").await;
    list.assert(200);
    let listed = list.json();
    assert_eq!(listed.as_array().unwrap().len(), 2);
    assert_eq!(listed[0]["installationId"], "another");
    let exact = client.get(&format!("{INSTALLATION}/metadata")).await;
    exact.assert(200);
    let exact = exact.json();
    assert_eq!(listed[1], exact);
    assert_eq!(
        exact,
        value!({
            "installationId": "demo", "generation": 1, "uid": 20001,
            "appId": "fixture.test", "archiveSha256": "0".repeat(64),
            "name": "Fixture", "entrypoint": "ui/index.html", "slots": ["navigation"],
            "permissionKeys": ["greet"], "routes": ["overview", "details"],
            "dialogs": ["confirm"], "events": ["updated"],
        })
    );
    let asset = client
        .get(&format!("{INSTALLATION}/assets/index.html"))
        .await;
    asset.assert(200);
    assert!(
        asset
            .headers
            .contains("content-type: application/octet-stream")
    );
    assert_eq!(asset.body, b"<h1>Fixture</h1>");
    let policy = client.get(OPERATION).await;
    policy.assert(200);
    assert_eq!(
        policy.json(),
        value!({
            "permissionKey": "greet",
            "resource": {
                "capability": {"id": "proxy.hosts.read.v1", "scope": "proxyHosts"},
                "resourceIdField": "resourceId",
            },
        })
    );
}

async fn assert_invalid_requests(client: &Client) {
    for (path, status) in [
        ("/v1/apps?unexpected=1", 400),
        ("http://localhost/v1/apps", 400),
        ("/other", 404),
        ("/v1/apps/", 404),
        ("/v1/apps/demo", 404),
        ("/v1/apps/demo/1", 404),
        ("/v1/apps/demo/1/metadata/", 404),
        ("/v1/apps/demo/01/metadata", 404),
        ("/v1/apps/demo/2/metadata", 412),
        ("/v1/apps/offline/1/metadata", 412),
        ("/v1/apps/demo/1/assets/../api/openapi.json", 404),
        ("/v1/apps/demo/1/assets/no-file", 404),
        ("/v1/apps/demo/1/assets/large.bin", 404),
        ("/v1/apps/demo/1/operations/absent", 404),
    ] {
        client.get(path).await.assert(status);
    }
    client
        .raw(b"GET /v1/apps HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec())
        .await
        .assert(400);
    client.request("PUT", OPERATION, "", b"").await.assert(404);
    client
        .request("GET", "/v1/apps", "", b"unexpected")
        .await
        .assert(400);
    client
        .request("POST", "/v1/apps/demo/1/metadata", "", b"")
        .await
        .assert(404);
    client
        .request("POST", "/v1/apps/demo/1/operations/bad/path", "", b"")
        .await
        .assert(404);
    for headers in [
        "Content-Type: application/json\r\n",
        "Idempotency-Key: caller-7\r\n",
        "Content-Type: application/json\r\nIdempotency-Key: spaces invalid\r\n",
        "Content-Type: application/json\r\nIdempotency-Key: first\r\nIdempotency-Key: duplicate\r\n",
        "Content-Type: text/plain\r\nIdempotency-Key: caller-7\r\n",
        "Content-Type: application/json\r\nContent-Type: application/json\r\nIdempotency-Key: caller-7\r\n",
    ] {
        client
            .request("POST", OPERATION, headers, REQUEST_BODY)
            .await
            .assert(400);
    }
    client
        .request(
            "POST",
            "/v1/apps/demo/1/operations/absent",
            "Content-Type: application/json\r\nIdempotency-Key: caller-7\r\n",
            b"{}",
        )
        .await
        .assert(404);
    for body in [
        b"[".as_slice(),
        br#"{"resourceId":"fixture","resourceId":"fixture","name":"Kevin"}"#.as_slice(),
        br#"{"name":"Kevin"}"#.as_slice(),
        br#"{"resourceId":"fixture","name":123}"#.as_slice(),
    ] {
        client.post(body).await.assert(400);
    }
    client
        .post(&vec![b'x'; MAX_JSON_BYTES + 1])
        .await
        .assert(413);
    let malformed = format!(
        "POST {OPERATION} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nIdempotency-Key: caller-7\r\nTransfer-Encoding: chunked\r\n\r\nz\r\n"
    );
    client.raw(malformed.into_bytes()).await.assert(400);
}

async fn assert_invocation(client: &Client, demo: &Publication, broker: &Broker) {
    let reply = client.request(
        "POST", OPERATION,
        "Content-Type: application/json\r\nIdempotency-Key: caller-7\r\nCookie: ignored\r\nAuthorization: ignored\r\n",
        REQUEST_BODY,
    ).await;
    reply.assert(200);
    assert_eq!(reply.json(), value!({"greeting": "Gude Kevin"}));
    for (status, expected) in [
        (StatusCode::FORBIDDEN, 412),
        (StatusCode::CONFLICT, 409),
        (StatusCode::GATEWAY_TIMEOUT, 504),
        (StatusCode::INTERNAL_SERVER_ERROR, 502),
    ] {
        *broker.reply.lock().unwrap() = BrokerReply {
            status,
            media: "text/plain",
            body: Bytes::from_static(b"private broker error"),
        };
        let reply = client.post(REQUEST_BODY).await;
        reply.assert(expected);
        assert!(reply.body.is_empty());
    }
    for (media, body) in [
        (
            "text/plain",
            Bytes::from_static(br#"{"greeting":"wrong media"}"#),
        ),
        (
            "application/json",
            Bytes::from_static(br#"{"greeting":"a","greeting":"b"}"#),
        ),
        (
            "application/json",
            Bytes::from_static(br#"{"greeting":10}"#),
        ),
        (
            "application/json",
            Bytes::from(vec![b'x'; MAX_JSON_BYTES + 1]),
        ),
    ] {
        *broker.reply.lock().unwrap() = BrokerReply {
            status: StatusCode::OK,
            media,
            body,
        };
        client.post(REQUEST_BODY).await.assert(502);
    }
    let held = demo
        .entry
        .operations
        .try_acquire_many(MAX_OPERATIONS_PER_INSTALLATION as u32)
        .unwrap();
    client.post(REQUEST_BODY).await.assert(429);
    drop(held);
    *broker.reply.lock().unwrap() = BrokerReply::success();
}

const PROVIDER_PATH: &str = "/v1/providers/monitored/monitor-main";
const PROVIDER_HEADERS: &str = "Content-Type: application/json\r\nIdempotency-Key: caller-7\r\n";
const PROVIDER_BODY: &[u8] = br#"{"profile":"monitoring","payload":{"limit":2}}"#;
const PROVIDER_RESULT: &[u8] = br#"{"profile":"monitoring","payload":{"samples":[]}}"#;

/// A broker that answers provider invocations for one published generation.
struct ProviderBroker {
    reply: Mutex<BrokerReply>,
    hold_calls: AtomicBool,
    entered: Notify,
    release: Notify,
}

impl ProviderBroker {
    fn bind(publication: &ProviderPublication, generation: &'static str) -> (Arc<Self>, Task) {
        let path = &publication.endpoint.broker_socket;
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(path).unwrap();
        let broker = Arc::new(Self {
            reply: Mutex::new(BrokerReply {
                status: StatusCode::OK,
                media: "application/json",
                body: Bytes::from_static(PROVIDER_RESULT),
            }),
            hold_calls: AtomicBool::new(false),
            entered: Notify::new(),
            release: Notify::new(),
        });
        let behavior = Arc::clone(&broker);
        let task = Task(tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    _ = connections.join_next(), if !connections.is_empty() => {},
                    accepted = listener.accept() => {
                        let (stream, _) = accepted.unwrap();
                        assert_eq!(stream.peer_cred().unwrap().uid(), 0);
                        let behavior = Arc::clone(&behavior);
                        connections.spawn(async move {
                            let service = service_fn(move |request: Request<Incoming>| {
                                let behavior = Arc::clone(&behavior);
                                async move {
                                    Ok::<_, std::convert::Infallible>(
                                        behavior.respond(request, generation).await,
                                    )
                                }
                            });
                            let _ = http1::Builder::new()
                                .keep_alive(false)
                                .serve_connection(TokioIo::new(stream), service)
                                .await;
                        });
                    }
                }
            }
        }));
        (broker, task)
    }

    async fn respond(&self, request: Request<Incoming>, generation: &str) -> Response<Full<Bytes>> {
        assert_eq!(request.method(), Method::POST);
        assert_eq!(request.uri().path(), "/app/v1/providers/monitor-main");
        assert_eq!(request.headers()["x-app-installation"], "monitored");
        assert_eq!(request.headers()["x-app-generation"], generation);
        assert_eq!(request.headers()["idempotency-key"], "caller-7");
        assert_eq!(request.headers()[header::CONTENT_TYPE], "application/json");
        for forbidden in [header::AUTHORIZATION, header::COOKIE] {
            assert!(!request.headers().contains_key(forbidden));
        }
        let body = request.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), PROVIDER_BODY);
        if self.hold_calls.load(Ordering::Acquire) {
            self.entered.notify_one();
            self.release.notified().await;
        }
        let reply = self.reply.lock().unwrap().clone();
        Response::builder()
            .status(reply.status)
            .header(header::CONTENT_TYPE, reply.media)
            .body(Full::new(reply.body))
            .unwrap()
    }
}

async fn assert_provider_invocations(client: &Client, registry: &Registry, app_root: &Path) {
    let invoke = || {
        client.request(
            "POST",
            PROVIDER_PATH,
            "Content-Type: application/json\r\nIdempotency-Key: caller-7\r\nCookie: ignored\r\nAuthorization: ignored\r\n",
            PROVIDER_BODY,
        )
    };
    // No generation of the installation is invocable yet.
    invoke().await.assert(404);
    let first = registry
        .providers
        .publish_in("monitored", 20_004, 3, app_root)
        .unwrap();
    let (broker, _task) = ProviderBroker::bind(&first, "3");
    let reply = invoke().await;
    reply.assert(200);
    assert_eq!(
        reply.json(),
        value!({"profile": "monitoring", "payload": {"samples": []}})
    );

    // The broker's decision maps onto the web socket without leaking its body.
    for (status, expected) in [
        (StatusCode::NOT_FOUND, 404),
        (StatusCode::BAD_REQUEST, 400),
        (StatusCode::UNSUPPORTED_MEDIA_TYPE, 400),
        (StatusCode::PAYLOAD_TOO_LARGE, 400),
        (StatusCode::CONFLICT, 409),
        (StatusCode::UNAUTHORIZED, 412),
        (StatusCode::FORBIDDEN, 412),
        (StatusCode::GATEWAY_TIMEOUT, 504),
        (StatusCode::SERVICE_UNAVAILABLE, 503),
    ] {
        *broker.reply.lock().unwrap() = BrokerReply {
            status,
            media: "application/problem+json",
            body: Bytes::from_static(b"private broker problem"),
        };
        let reply = invoke().await;
        reply.assert(expected);
        assert!(reply.body.is_empty());
    }
    for (media, body) in [
        ("text/plain", Bytes::from_static(PROVIDER_RESULT)),
        (
            "application/json",
            Bytes::from(vec![b'x'; MAX_JSON_BYTES + 1]),
        ),
    ] {
        *broker.reply.lock().unwrap() = BrokerReply {
            status: StatusCode::OK,
            media,
            body,
        };
        invoke().await.assert(502);
    }
    *broker.reply.lock().unwrap() = BrokerReply {
        status: StatusCode::OK,
        media: "application/json",
        body: Bytes::from_static(PROVIDER_RESULT),
    };

    for (path, headers, status) in [
        ("/v1/providers/monitored", PROVIDER_HEADERS, 404),
        ("/v1/providers/monitored/", PROVIDER_HEADERS, 404),
        (
            "/v1/providers/Monitored/monitor-main",
            PROVIDER_HEADERS,
            404,
        ),
        (
            "/v1/providers/monitored/monitor-main/extra",
            PROVIDER_HEADERS,
            404,
        ),
        ("/v1/providers/unknown/monitor-main", PROVIDER_HEADERS, 404),
        (PROVIDER_PATH, "Content-Type: application/json\r\n", 400),
        (PROVIDER_PATH, "Idempotency-Key: caller-7\r\n", 400),
        (
            PROVIDER_PATH,
            "Content-Type: text/plain\r\nIdempotency-Key: caller-7\r\n",
            400,
        ),
        (
            PROVIDER_PATH,
            "Content-Type: application/json\r\nIdempotency-Key: Caller-7\r\n",
            400,
        ),
    ] {
        client
            .request("POST", path, headers, PROVIDER_BODY)
            .await
            .assert(status);
    }
    client
        .request(
            "POST",
            PROVIDER_PATH,
            PROVIDER_HEADERS,
            &vec![b' '; MAX_JSON_BYTES + 1],
        )
        .await
        .assert(413);

    let held = first
        .endpoint
        .calls
        .try_acquire_many(providers::MAX_CALLS_PER_INSTALLATION as u32)
        .unwrap();
    invoke().await.assert(429);
    drop(held);

    // A newer generation withdraws the older one, also from an invocation in flight.
    broker.hold_calls.store(true, Ordering::Release);
    let inflight = tokio::spawn({
        let client = client.clone();
        async move {
            client
                .request("POST", PROVIDER_PATH, PROVIDER_HEADERS, PROVIDER_BODY)
                .await
        }
    });
    timeout(Duration::from_secs(3), broker.entered.notified())
        .await
        .unwrap();
    let second = registry
        .providers
        .publish_in("monitored", 20_004, 4, app_root)
        .unwrap();
    inflight.await.unwrap().assert(412);
    broker.release.notify_one();
    // The new generation's broker is not listening yet.
    invoke().await.assert(412);
    let (_second_broker, _second_task) = ProviderBroker::bind(&second, "4");
    invoke().await.assert(200);
    // Dropping the replaced publication leaves the newer one in place.
    drop(first);
    invoke().await.assert(200);
    drop(second);
    invoke().await.assert(404);
}
