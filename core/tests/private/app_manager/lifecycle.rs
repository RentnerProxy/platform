use super::super::ui::tests::manager_catalog;
use super::super::*;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode, body::Incoming, service::service_fn};
use hyper_util::rt::TokioIo;
use std::{
    convert::Infallible,
    fs,
    os::unix::fs::{OpenOptionsExt, PermissionsExt, chown},
    process::Stdio,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    process::{Child, Command as Process},
};

#[path = "lifecycle/published_greeting.rs"]
mod published_greeting;

const ID: &str = "fixture-install";
const UNCLAIMED: &str = "never-provisioned";
const INTERRUPTED: &str = "interrupted-claim";
const RESUMED_REMOVAL: &str = "resumed-removal";
const RESUMED_PURGE: &str = "resumed-purge";
/// While this file exists next to the authority socket, `removable` checks fail as unavailable.
const REFUSE_REMOVAL: &str = "refuse-removal";
/// With this variable, the authority fixture records every grant publication in the named file,
/// also for an activated generation, instead of accepting only an empty set before activation.
const GRANT_LOG: &str = "RENTNERPROXY_TEST_GRANT_LOG";
/// While this file exists next to the authority socket, grant publications for an activated
/// generation fail as unavailable.
const REFUSE_GRANTS: &str = "refuse-grants";
const UID: u32 = 59553;
const ROOT: &str = "/var/lib/rentnerproxy/app-manager";
const SOCKET: &str = "/run/rentnerproxy/app-api/web.sock";

struct CatalogServer {
    stop: Arc<AtomicBool>,
    task: Option<std::thread::JoinHandle<()>>,
}

impl CatalogServer {
    fn start(root: &Path, backend: &Path) -> (Self, PathBuf, Vec<StagedPackage>) {
        use std::{
            io::{BufRead, BufReader, Read, Write},
            net::TcpListener,
        };

        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let certificate = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        fs::write(root.join("catalog-ca.pem"), certificate.cert.pem()).unwrap();
        let tls = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![certificate.cert.der().clone()],
                    rustls::pki_types::PrivatePkcs8KeyDer::from(
                        certificate.signing_key.serialize_der(),
                    )
                    .into(),
                )
                .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let origin = format!("https://{}/", listener.local_addr().unwrap());
        let (config, packages, files) =
            crate::app_install::tests::lifecycle_packages(root, backend, &origin);
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let task = std::thread::spawn(move || {
            while !stopping.load(Ordering::Acquire) {
                let (socket, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                    Err(error) => panic!("Catalog fixture listener failed: {error}"),
                };
                let respond = || -> io::Result<()> {
                    socket.set_nonblocking(false)?;
                    socket.set_read_timeout(Some(Duration::from_secs(3)))?;
                    socket.set_write_timeout(Some(Duration::from_secs(3)))?;
                    let connection = rustls::ServerConnection::new(Arc::clone(&tls))
                        .map_err(io::Error::other)?;
                    let mut stream = rustls::StreamOwned::new(connection, socket);
                    let mut head = String::new();
                    BufReader::new((&mut stream).take(16_384)).read_line(&mut head)?;
                    let path = head
                        .strip_prefix("GET /")
                        .and_then(|line| line.split_once(' '))
                        .map(|(path, _)| path);
                    let (status, body) = match path.and_then(|name| files.get(name)) {
                        Some(body) => ("200 OK", body.as_slice()),
                        None => ("404 Not Found", b"".as_slice()),
                    };
                    write!(
                        stream,
                        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )?;
                    stream.write_all(body)?;
                    stream.conn.send_close_notify();
                    stream.flush()
                };
                if let Err(error) = respond() {
                    eprintln!("Catalog fixture connection failed: {error}");
                }
            }
        });
        (
            Self {
                stop,
                task: Some(task),
            },
            config,
            packages,
        )
    }
}

impl Drop for CatalogServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = self.task.take().expect("catalog fixture thread").join();
    }
}

/// What the fake authority has recorded for one registered generation.
struct Recorded {
    activated: bool,
    declared: bool,
    providers: Option<Value>,
}

const FIXTURE_PROVIDERS: &str =
    r#"[{"id":"fixture-monitor","profile":"monitoring","version":"1.0.0"}]"#;

async fn authority(
    request: Request<Incoming>,
    generations: Arc<Mutex<BTreeMap<u64, Recorded>>>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    assert_eq!(
        request.headers()["authorization"],
        "Bearer local-lifecycle-fixture"
    );
    let headers = request.headers().clone();
    let body = request.into_body().collect().await.unwrap().to_bytes();
    if method == hyper::Method::GET && path == "/platform/v1/context" {
        assert!(body.is_empty(), "Context request must not have a body");
        let installation_id = headers["x-app-installation"].to_str().unwrap();
        let expected_id =
            std::env::var("RENTNERPROXY_TEST_APP_INSTALLATION").unwrap_or_else(|_| ID.to_owned());
        assert_eq!(installation_id, expected_id);
        let app_id = headers["x-rentnerproxy-app-id"].to_str().unwrap();
        assert_eq!(app_id, "rentnerproxy.greeting");
        let generation = headers["x-app-generation"]
            .to_str()
            .unwrap()
            .parse::<u64>()
            .unwrap();
        let uid = headers["x-rentnerproxy-app-uid"]
            .to_str()
            .unwrap()
            .parse::<u32>()
            .unwrap();
        assert!((20_000..=59_999).contains(&uid));
        // The app reads its context while the registered generation prepares to start.
        assert!(generations.lock().unwrap().contains_key(&generation));
        let context = json!({
            "appId": app_id,
            "installationId": installation_id,
            "generation": generation,
            "runtimeProfile": "rentnerproxy-linux-v1",
            "versions": {
                "appProtocol": "1.0.0",
                "platformApi": "1.0.0",
                "uiBridge": "1.0.0",
            },
            "capabilities": [],
        });
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(context.to_string())))
            .unwrap());
    }
    let value: Value = serde_json::from_slice(&body)
        .unwrap_or_else(|error| panic!("Invalid gateway fixture request {method} {path}: {error}"));
    if let Some(uid) = match value["identity"]["installationId"].as_str() {
        Some(UNCLAIMED) => Some(UID + 1),
        Some(INTERRUPTED) => Some(UID + 2),
        Some(RESUMED_REMOVAL) => Some(UID + 3),
        Some(RESUMED_PURGE) => Some(UID + 4),
        _ => None,
    } {
        assert_eq!(value["identity"]["uid"], uid);
        let status = match path.rsplit('/').next().unwrap() {
            "register" => StatusCode::SERVICE_UNAVAILABLE,
            "retire" | "workers-stopped" | "removable" | "purge-data" => StatusCode::NO_CONTENT,
            action => panic!("unexpected unregistered fixture action {action}"),
        };
        return Ok(Response::builder()
            .status(status)
            .body(Full::new(Bytes::new()))
            .unwrap());
    }
    let uid = value["identity"]["uid"].as_u64().unwrap();
    if let Ok(expected_id) = std::env::var("RENTNERPROXY_TEST_APP_INSTALLATION") {
        assert_eq!(value["identity"]["installationId"], expected_id);
        if let Ok(expected_uid) = std::env::var("RENTNERPROXY_TEST_APP_UID") {
            assert_eq!(uid, expected_uid.parse::<u64>().unwrap());
        } else {
            assert!((20_000..=59_999).contains(&uid));
        }
    } else {
        assert_eq!(value["identity"]["installationId"], ID);
        assert_eq!(uid, u64::from(UID));
    }
    let generation = value["identity"]["generation"].as_u64().unwrap();
    let mut states = generations.lock().unwrap();
    let action = path.strip_prefix("/internal/v1/app-generations/").unwrap();
    if action == "lease" {
        if !states.contains_key(&generation) {
            return Ok(Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Full::new(Bytes::new()))
                .unwrap());
        }
        let expires = (time::OffsetDateTime::now_utc().unix_timestamp() + 30) * 1000;
        return Ok(Response::new(Full::new(Bytes::from(
            json!({"expiresAt":expires}).to_string(),
        ))));
    }
    let mut status = StatusCode::NO_CONTENT;
    match action {
        "register" => {
            assert!(states.is_empty());
            // Every launch sends the manifest's declared profiles, even when empty.
            let expected = if value["identity"]["appId"] == "rentnerproxy.greeting" {
                json!([])
            } else {
                json!(["monitoring"])
            };
            assert_eq!(value["providerProfiles"], expected);
            // A manifest without incident categories registers an empty declaration.
            assert_eq!(value["incidentCategories"], json!([]));
            states.insert(
                generation,
                Recorded {
                    activated: false,
                    declared: expected != json!([]),
                    providers: None,
                },
            );
        }
        "providers" => {
            // Only the registered, not yet activated, current generation may record
            // providers, and only exactly the fixture app's advertisement.
            let current = states.keys().next_back() == Some(&generation);
            let fixture: Value = serde_json::from_str(FIXTURE_PROVIDERS).unwrap();
            match states.get_mut(&generation) {
                Some(state)
                    if current
                        && !state.activated
                        && state.declared
                        && value["providers"] == fixture =>
                {
                    state.providers = Some(value["providers"].clone());
                }
                _ => status = StatusCode::CONFLICT,
            }
        }
        "grants" => {
            let activated = states.get(&generation).map(|state| state.activated);
            if let Some(log) = std::env::var_os(GRANT_LOG) {
                // A revocation replaces the grants of the activated generation, as the web
                // authority does. A retired generation has none to replace.
                match activated {
                    None => status = StatusCode::CONFLICT,
                    Some(true) if Path::new(SOCKET).with_file_name(REFUSE_GRANTS).exists() => {
                        status = StatusCode::SERVICE_UNAVAILABLE;
                    }
                    Some(activated) => {
                        let record = json!({
                            "generation": generation,
                            "activated": activated,
                            "grants": value["grants"],
                        });
                        let mut file = fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(log)
                            .unwrap();
                        std::io::Write::write_all(&mut file, format!("{record}\n").as_bytes())
                            .unwrap();
                    }
                }
            } else {
                assert_eq!(activated, Some(false));
                assert_eq!(value["grants"], json!([]));
            }
            if status == StatusCode::NO_CONTENT {
                fs::write(
                    Path::new(SOCKET).with_file_name("last-grants-generation"),
                    generation.to_string(),
                )
                .unwrap();
            }
        }
        "activate" => {
            let state = states.get_mut(&generation).unwrap();
            assert!(!state.activated);
            // Readiness waits for the 204, so declared providers precede activation.
            assert_eq!(state.providers.is_some(), state.declared);
            state.activated = true;
        }
        "renew" => assert!(states.contains_key(&generation)),
        "provider" => {
            // Only the live generation serves the provider it recorded.
            let recorded = states
                .get(&generation)
                .filter(|state| state.activated)
                .and_then(|state| state.providers.as_ref())
                .and_then(|providers| {
                    providers
                        .as_array()?
                        .iter()
                        .find(|provider| provider["id"] == value["providerId"])
                        .cloned()
                });
            return Ok(match recorded {
                Some(provider) => Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "application/json")
                    .body(Full::new(Bytes::from(provider.to_string())))
                    .unwrap(),
                None => Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            });
        }
        "retire" => {
            states.remove(&generation);
        }
        "workers-stopped" | "purge-data" => assert!(states.is_empty()),
        "removable" => {
            // An unavailable web authority cannot confirm that the installation is removable.
            if Path::new(SOCKET).with_file_name(REFUSE_REMOVAL).exists() {
                status = StatusCode::SERVICE_UNAVAILABLE;
            }
        }
        _ => panic!("unexpected private action {action}"),
    }
    Ok(Response::builder()
        .status(status)
        .body(Full::new(Bytes::new()))
        .unwrap())
}

#[tokio::test]
#[ignore = "private subprocess of the isolated lifecycle fixture"]
async fn authority_fixture() {
    assert_eq!(unsafe { libc::geteuid() }, 10002);
    let listener = UnixListener::bind(SOCKET).unwrap();
    let states = Arc::new(Mutex::new(BTreeMap::new()));
    loop {
        let (stream, _) = listener.accept().await.unwrap();
        let states = states.clone();
        tokio::spawn(async move {
            hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    TokioIo::new(stream),
                    service_fn(move |req| authority(req, states.clone())),
                )
                .await
                .unwrap();
        });
    }
}

async fn invoke(controller: &Path, args: &[&str]) -> io::Result<Value> {
    let output = timeout(
        Duration::from_secs(20),
        Process::new(controller)
            .arg("--app-control")
            .args(args)
            .kill_on_drop(true)
            .output(),
    )
    .await??;
    if !output.status.success() {
        return Err(io::Error::other(
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ));
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}

enum BootState {
    Running,
    Disabled,
    Recovery,
    MissingData,
}

async fn manager_status() -> io::Result<Value> {
    let mut stream = UnixStream::connect("/run/rentnerproxy/app-manager/control.sock").await?;
    stream.write_all(br#"{"action":"status"}"#).await?;
    stream.shutdown().await?;
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await?;
    let reply: Value = serde_json::from_slice(&bytes)?;
    Ok(reply["result"].clone())
}

async fn mount_manager(
    controller: &Path,
    config: &Path,
    token: &Path,
    expected: BootState,
) -> Child {
    let mut command = Process::new(controller);
    // Only the fixture's manager subprocess inherits this restrictive umask.
    unsafe {
        command.pre_exec(|| {
            libc::umask(0o077);
            Ok(())
        });
    }
    let mut child = command
        .arg("--app-manager")
        .arg(config)
        .env(crate::config::CONTROLLER_TOKEN_FILE_ENV, token)
        .env("SSL_CERT_FILE", config.with_file_name("catalog-ca.pem"))
        .env("NO_PROXY", "127.0.0.1")
        .env("no_proxy", "127.0.0.1")
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    timeout(Duration::from_secs(20), async {
        loop {
            assert!(child.try_wait().unwrap().is_none());
            // Poll over the private socket without spawning short-lived process trees
            // while startup is verifying the appliance's process identities.
            if manager_status().await.is_ok_and(|state| {
                state[ID]["running"] == matches!(expected, BootState::Running)
                    && state[ID]["recoveryRequired"] == matches!(expected, BootState::Recovery)
            }) {
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    child
}

async fn halt(child: &mut Child) {
    let pid = i32::try_from(child.id().unwrap()).unwrap();
    // The test still owns this live, unreaped child.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
    assert!(
        timeout(Duration::from_secs(18), child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
}

async fn backup_files(controller: &Path, config: &Path, token: &Path, temporary: &Path) {
    let command = |action: &str| {
        let mut command = Process::new(controller);
        command
            .args(["--app-backup", action])
            .env("RENTNERPROXY_APP_INSTALLER_CONFIG", config);
        command
    };
    let data = super::super::storage::directory(UID).join("data");
    let note = data.join("synthetic-note");
    fs::write(&note, b"offline fixture").unwrap();
    chown(&note, Some(UID), Some(UID)).unwrap();
    let output = command("capture").output().await.unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut manifest: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(manifest["installations"][ID]["active"]["version"], "1.0.0");
    assert_eq!(manifest["installations"][ID]["storageClaimed"], true);
    assert_eq!(
        manifest["installations"][UNCLAIMED]["storageClaimed"],
        false
    );
    assert_eq!(manifest["installations"][UNCLAIMED]["generation"], 1);
    assert_eq!(manifest["installations"][UNCLAIMED]["removal"], "removed");
    assert!(manifest["data"].get((UID + 1).to_string()).is_none());
    assert_eq!(
        manifest["installations"][INTERRUPTED]["storageClaimed"],
        false
    );
    assert!(manifest["data"].get((UID + 2).to_string()).is_none());
    let snapshot = temporary.join("app-snapshot");
    fs::write(&snapshot, output.stdout).unwrap();
    fs::write(&note, b"changed fixture").unwrap();
    for action in ["inspect", "verify", "restore"] {
        assert!(
            command(action)
                .arg(&snapshot)
                .status()
                .await
                .unwrap()
                .success(),
            "{action}"
        );
    }
    assert_eq!(fs::read(&note).unwrap(), b"offline fixture");
    assert!(!command("empty").output().await.unwrap().status.success());
    for legacy in [false, true] {
        let mut journal = Journal::open(Path::new(ROOT)).unwrap();
        let mut slot = journal.slot(ID).unwrap().clone();
        if legacy {
            slot.storage_claimed = None;
            journal.save(ID, slot.clone()).unwrap();
        }
        drop(journal);
        let output = command("capture").output().await.unwrap();
        assert!(output.status.success());
        manifest = serde_json::from_slice(&output.stdout).unwrap();
        fs::write(&snapshot, output.stdout).unwrap();
        fs::remove_dir_all(&data).unwrap();
        let mut child = mount_manager(controller, config, token, BootState::MissingData).await;
        let err = invoke(controller, &["start", ID]).await.unwrap_err();
        assert!(
            err.to_string().contains("unavailable committed data"),
            "{err}"
        );
        if legacy {
            let reservation = storage::directory(UID);
            let saved = reservation.with_file_name("fixture-saved-reservation");
            fs::rename(&reservation, &saved).unwrap();
            let err = invoke(controller, &["start", ID]).await.unwrap_err();
            assert!(
                err.to_string().contains("unavailable committed data"),
                "{err}"
            );
            assert!(!reservation.exists());
            fs::rename(saved, reservation).unwrap();
        }
        halt(&mut child).await;
        assert!(!data.exists());
        let journal = Journal::open(Path::new(ROOT)).unwrap();
        assert_eq!(
            serde_json::to_value(journal.slot(ID).unwrap()).unwrap(),
            serde_json::to_value(&slot).unwrap()
        );
        drop(journal);
        assert!(!command("capture").output().await.unwrap().status.success());
        for action in ["verify", "restore"] {
            assert!(
                command(action)
                    .arg(&snapshot)
                    .status()
                    .await
                    .unwrap()
                    .success(),
                "{action}"
            );
        }
        assert_eq!(fs::read(&note).unwrap(), b"offline fixture");
    }
    let alias = data.join("fixture-hardlink");
    fs::hard_link(&note, &alias).unwrap();
    assert!(!command("capture").output().await.unwrap().status.success());
    fs::remove_file(alias).unwrap();
    manifest["installations"][ID]["active"]["archiveSha256"] = "0".repeat(64).into();
    fs::write(&snapshot, serde_json::to_vec(&manifest).unwrap()).unwrap();
    assert!(
        !command("restore")
            .arg(&snapshot)
            .output()
            .await
            .unwrap()
            .status
            .success()
    );
    assert_eq!(fs::read(&note).unwrap(), b"offline fixture");
}

async fn check_control_boundary(controller: &Path, temporary: &Path) {
    for arguments in [
        &["unknown"][..],
        &["stop", "../invalid"],
        &["stop", "missing-app"],
        &["stage", ID, "example.other", "1.0.0"],
        &["rollback", ID],
    ] {
        assert!(
            invoke(controller, arguments).await.is_err(),
            "{arguments:?}"
        );
    }
    let long_version = "1".repeat(129);
    assert!(
        invoke(controller, &["stage", ID, "example.probe", &long_version])
            .await
            .is_err()
    );
    let socket = "/run/rentnerproxy/app-manager/control.sock";
    for malformed in [b"null".to_vec(), vec![b' '; 96 * 1024 + 1]] {
        let mut stream = UnixStream::connect(socket).await.unwrap();
        stream.write_all(&malformed).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.unwrap();
        let reply: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(reply["ok"], false);
    }
    let grants = temporary.join("grants.json");
    fs::write(&grants, "[]").unwrap();
    let path = grants.to_str().unwrap();
    fs::set_permissions(&grants, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(invoke(controller, &["activate", ID, path]).await.is_err());
    fs::set_permissions(&grants, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&grants, "{").unwrap();
    assert!(invoke(controller, &["activate", ID, path]).await.is_err());
    // Root's escape hatch is validated like an approval: a capability the staged release does
    // not declare, or another provider profile, is refused before anything changes.
    let before = invoke(controller, &["status"]).await.unwrap();
    let published = grant_log().len();
    for undeclared in [
        json!({
            "capability": {"id": "proxy.hosts.read.v1", "scope": "proxyHosts"},
            "resourceId": "0b6f3c0e-8d1a-4f43-9c2e-1d7a5b9e4f21",
            "allowService": true,
        }),
        json!({
            "capability": {"id": "app.provider.register", "scope": "providerProfiles"},
            "resourceId": "oidc",
            "allowService": true,
        }),
    ] {
        fs::write(&grants, serde_json::to_vec(&json!([undeclared])).unwrap()).unwrap();
        let refused = invoke(controller, &["activate", ID, path])
            .await
            .unwrap_err();
        assert!(
            refused
                .to_string()
                .contains("Grants exceed what the staged release requests"),
            "{refused}"
        );
    }
    assert_eq!(invoke(controller, &["status"]).await.unwrap(), before);
    assert_eq!(grant_log().len(), published);
    fs::write(&grants, "[]").unwrap();
    invoke(controller, &["activate", ID, path]).await.unwrap();
    // The activation published root's empty approval for its own generation.
    let status = invoke(controller, &["status"]).await.unwrap();
    assert_eq!(
        last_grants(),
        json!({"generation": status[ID]["generation"], "activated": false, "grants": []})
    );
}

/// Every grant publication the authority fixture recorded, oldest first.
fn grant_log() -> Vec<Value> {
    fs::read_to_string(Path::new(SOCKET).with_file_name("grant-log.jsonl"))
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn last_grants() -> Value {
    grant_log().pop().expect("a recorded grant publication")
}

/// The provider registration grant the fixture app's releases request.
fn monitoring_grant() -> Value {
    json!({
        "capability": {"id": "app.provider.register", "scope": "providerProfiles"},
        "resourceId": "monitoring",
        "allowService": true,
    })
}

fn catalog_row(view: &Value) -> &Value {
    view["installations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["installationId"] == ID)
        .unwrap()
}

fn lifecycle_input(action: &str, row: &Value, target: Option<&Value>) -> Value {
    let mut request = json!({
        "action": action,
        "installationId": ID,
        "expected": {
            "generation": row["generation"],
            "version": row["version"],
            "archiveSha256": row["archiveSha256"],
        },
    });
    if let Some(target) = target {
        request["target"] = target.clone();
    }
    request
}

/// The restarted generation's provider is invocable over the web socket, through its
/// broker and the authority, while an unregistered provider ID is not.
async fn assert_provider_invocation() {
    async fn call(provider: &str) -> (u16, Value) {
        let path = format!("/v1/providers/{ID}/{provider}");
        crate::app_manager::ui::tests::fixture_request(
            "POST",
            &path,
            "Content-Type: application/json\r\nIdempotency-Key: lifecycle-probe\r\n",
            br#"{"profile":"monitoring","payload":{"limit":1}}"#,
        )
        .await
    }
    assert_eq!(
        call("fixture-monitor").await,
        (
            200,
            json!({"profile": "monitoring", "payload": {"samples": []}})
        )
    );
    assert_eq!(call("other-monitor").await.0, 404);
}

async fn ui_mutate(request: &Value, expected_status: u16) {
    let initial = manager_catalog(Some(request), expected_status).await;
    if expected_status != 202 {
        return;
    }
    assert_eq!(initial["status"], "pending");
    let operation = ui_outcome(request).await;
    assert_eq!(operation["status"], "succeeded", "{operation}");
}

/// Wait for the accepted lifecycle `request` to finish and return its operation.
async fn ui_outcome(request: &Value) -> Value {
    timeout(Duration::from_secs(20), async {
        loop {
            let view = manager_catalog(None, 200).await;
            let operation = &view["lifecycle"];
            if operation["status"] != "pending" {
                assert_eq!(operation["action"], request["action"]);
                break operation.clone();
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap()
}

async fn ui_action(action: &str, expected_status: u16) {
    let view = manager_catalog(None, 200).await;
    ui_mutate(
        &lifecycle_input(action, catalog_row(&view), None),
        expected_status,
    )
    .await;
}

async fn ui_signed_switch(controller: &Path, first: &Release, second: &Release) -> Value {
    let view = manager_catalog(None, 200).await;
    let updated_by_cli = catalog_row(&view);
    assert_eq!(
        updated_by_cli["previous"]["archiveSha256"],
        first.archive_sha256
    );
    let rollback = lifecycle_input(
        "rollback",
        updated_by_cli,
        Some(&updated_by_cli["previous"]),
    );
    ui_mutate(&rollback, 202).await;

    let view = timeout(Duration::from_secs(10), async {
        loop {
            let view = manager_catalog(None, 200).await;
            if view["state"] == "ready" {
                break view;
            }
            assert_eq!(view["state"], "loading", "{view}");
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    let active = catalog_row(&view);
    assert_eq!(active["archiveSha256"], first.archive_sha256);
    assert_eq!(active["update"]["version"], second.version);
    assert_eq!(active["update"]["archiveSha256"], second.archive_sha256);
    // The restored release predates recorded approvals, so it carries none to the update,
    // which requests its provider registration.
    assert_eq!(active["grants"], Value::Null);
    assert_eq!(active["updateRequiresApproval"], true);
    let update = lifecycle_input("update", active, Some(&active["update"]));
    let mut invalid = update.clone();
    invalid["target"]["archiveSha256"] = "0".repeat(64).into();
    ui_mutate(&invalid, 409).await;
    let mut stale = update.clone();
    stale["expected"]["generation"] = updated_by_cli["generation"].clone();
    ui_mutate(&stale, 409).await;
    // Without an approval, or with a wider one, the update is refused before anything changes.
    let published = grant_log().len();
    ui_mutate(&update, 422).await;
    let mut wider = update.clone();
    let mut oidc = monitoring_grant();
    oidc["resourceId"] = "oidc".into();
    wider["approval"] = json!([monitoring_grant(), oidc]);
    ui_mutate(&wider, 422).await;
    assert_eq!(grant_log().len(), published);
    assert_eq!(
        catalog_row(&manager_catalog(None, 200).await)["generation"],
        active["generation"]
    );
    let mut approved = update.clone();
    approved["approval"] = json!([monitoring_grant()]);
    ui_mutate(&approved, 202).await;
    let current = invoke(controller, &["status"]).await.unwrap()[ID].clone();
    // The update published exactly the approved grants for its own generation.
    assert_eq!(
        last_grants(),
        json!({
            "generation": current["generation"],
            "activated": false,
            "grants": [monitoring_grant()],
        })
    );
    let row = catalog_row(&manager_catalog(None, 200).await).clone();
    assert_eq!(row["grants"], json!([monitoring_grant()]));
    assert_eq!(current["active"], second.version);
    assert_eq!(current["previous"], first.version);
    assert_eq!(current["uid"], UID);
    assert_eq!(
        current["generation"].as_u64().unwrap(),
        active["generation"].as_u64().unwrap() + 1
    );
    current
}

/// The catalog view once a refreshed listing offers updates again.
async fn ready_view() -> Value {
    timeout(Duration::from_secs(10), async {
        loop {
            let view = manager_catalog(None, 200).await;
            if view["state"] == "ready" {
                break view;
            }
            assert_eq!(view["state"], "loading", "{view}");
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap()
}

fn revocation(row: &Value, grant: &Value) -> Value {
    let mut request = lifecycle_input("revoke", row, None);
    request["grants"] = json!([{
        "capability": grant["capability"],
        "resourceId": grant["resourceId"],
    }]);
    request
}

/// Revoke the running update's approved grant without a restart, then approve it again with
/// a rollback and an update. The catalog is reachable, and the update is running.
async fn check_revocation(controller: &Path) {
    let before = installation(controller).await;
    let view = manager_catalog(None, 200).await;
    let revoke = revocation(catalog_row(&view), &monitoring_grant());
    ui_mutate(&revoke, 202).await;
    // The live generation lost the grant at once and keeps running.
    assert_eq!(
        last_grants(),
        json!({"generation": before["generation"], "activated": true, "grants": []})
    );
    assert_eq!(installation(controller).await, before);
    let row = catalog_row(&manager_catalog(None, 200).await).clone();
    assert_eq!(row["grants"], json!([]));
    // Every stored approval lost it, and a revoked grant cannot be revoked again.
    assert!(stored_without_monitoring());
    ui_mutate(&revocation(&row, &monitoring_grant()), 409).await;

    let rollback = lifecycle_input("rollback", &row, Some(&row["previous"]));
    ui_mutate(&rollback, 202).await;
    let view = ready_view().await;
    let active = catalog_row(&view);
    let mut update = lifecycle_input("update", active, Some(&active["update"]));
    update["approval"] = json!([monitoring_grant()]);
    ui_mutate(&update, 202).await;
    let current = installation(controller).await;
    assert_eq!(current["active"], before["active"]);
    assert_eq!(
        last_grants(),
        json!({
            "generation": current["generation"],
            "activated": false,
            "grants": [monitoring_grant()],
        })
    );

    // Root stages the running archive again and activates it with an empty replacement, which
    // never becomes ready. Only the candidate generation receives the replacement. The fallback
    // restart runs with the approval the release had, and the journal never records it.
    let version = current["active"].as_str().unwrap();
    invoke(controller, &["stage", ID, "example.probe", version])
        .await
        .unwrap();
    assert_eq!(installation(controller).await["candidate"], version);
    let marker = storage::directory(UID).join("data/fixture-never-ready");
    fs::write(&marker, []).unwrap();
    let error = invoke(controller, &["activate", ID]).await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("Previous release restarted with previously approved grants"),
        "{error}"
    );
    assert!(!marker.exists(), "the candidate did not start");
    let restarted = installation(controller).await;
    assert_eq!(restarted["running"], true);
    assert_eq!(restarted["active"], version);
    let log = grant_log();
    assert_eq!(
        log[log.len() - 2..],
        [
            json!({
                "generation": restarted["generation"].as_u64().unwrap() - 1,
                "activated": false,
                "grants": [],
            }),
            json!({
                "generation": restarted["generation"],
                "activated": false,
                "grants": [monitoring_grant()],
            }),
        ]
    );
    let journal = fs::read(Path::new(ROOT).join("journal.json")).unwrap();
    let journal: Value = serde_json::from_slice(&journal).unwrap();
    let approvals = journal["installations"][ID]["approvals"]
        .as_object()
        .unwrap();
    assert!(
        approvals
            .values()
            .all(|approval| approval["grants"] == json!([monitoring_grant()])),
        "{journal}"
    );
}

/// Whether no stored approval of `ID` holds the monitoring registration grant.
fn stored_without_monitoring() -> bool {
    // The running manager holds the journal lock, so read the persisted journal itself.
    let journal = fs::read(Path::new(ROOT).join("journal.json")).unwrap();
    let state: Value = serde_json::from_slice(&journal).unwrap();
    let approvals = state["installations"][ID]["approvals"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    !approvals.is_empty()
        && approvals.values().all(|approval| {
            !approval["grants"]
                .as_array()
                .unwrap()
                .contains(&monitoring_grant())
        })
}

/// Restarts, an interrupted transition and recovery publish the approval of the committed
/// release again. A revocation that the live generation cannot apply fences it.
async fn check_approved_restarts(
    controller: &Path,
    config: &Path,
    token: &Path,
    manager: &mut Child,
) {
    invoke(controller, &["stop", ID]).await.unwrap();
    invoke(controller, &["start", ID]).await.unwrap();
    let started = installation(controller).await;
    assert_eq!(
        last_grants(),
        json!({
            "generation": started["generation"],
            "activated": false,
            "grants": [monitoring_grant()],
        })
    );

    // An activation stopped after it may have published new grants. The boot restarts the
    // committed release with its own approval instead of clearing every grant.
    halt(manager).await;
    let interrupted = preseed(|slot| {
        slot.generation += 1;
        slot.pending_fence = true;
        slot.recovery_required = true;
        slot.grants_uncertain = Some(true);
    });
    *manager = mount_manager(controller, config, token, BootState::Running).await;
    assert_eq!(
        last_grants(),
        json!({
            "generation": interrupted.generation + 2,
            "activated": false,
            "grants": [monitoring_grant()],
        })
    );

    // The authority cannot apply a revocation to the live generation. The manager fences it
    // and requires recovery, which starts the release with the reduced approval.
    let refusal = Path::new(SOCKET).with_file_name(REFUSE_GRANTS);
    fs::write(&refusal, []).unwrap();
    let view = manager_catalog(None, 200).await;
    let revoke = revocation(catalog_row(&view), &monitoring_grant());
    assert_eq!(
        manager_catalog(Some(&revoke), 202).await["status"],
        "pending"
    );
    let failed = ui_outcome(&revoke).await;
    assert_eq!(failed["status"], "failed", "{failed}");
    assert_eq!(failed["error"], "revokedAppStopped", "{failed}");
    let fenced = installation(controller).await;
    assert_eq!(fenced["running"], false);
    assert_eq!(fenced["recoveryRequired"], true);
    assert!(stored_without_monitoring());
    fs::remove_file(&refusal).unwrap();
    ui_action("recover", 202).await;
    let recovered = installation(controller).await;
    assert_eq!(recovered["running"], true);
    assert_eq!(
        last_grants(),
        json!({"generation": recovered["generation"], "activated": false, "grants": []})
    );
}

async fn check_process_recovery(
    controller: &Path,
    config: &Path,
    token: &Path,
    manager: &mut Child,
) {
    let data = super::super::storage::directory(UID).join("data");
    fs::write(data.join("fixture-exit"), []).unwrap();
    timeout(Duration::from_secs(8), async {
        loop {
            let state = invoke(controller, &["status"]).await.unwrap();
            if state[ID]["running"] == false {
                assert_eq!(state[ID]["recoveryRequired"], true);
                assert_eq!(state[ID]["desiredRunning"], true);
                break;
            }
            sleep(Duration::from_millis(75)).await;
        }
    })
    .await
    .unwrap();
    ui_action("recover", 202).await;
    ui_action("deactivate", 202).await;
    let stopped = invoke(controller, &["status"]).await.unwrap();
    assert_eq!(stopped[ID]["running"], false);
    assert_eq!(stopped[ID]["desiredRunning"], false);
    halt(manager).await;
    *manager = mount_manager(controller, config, token, BootState::Disabled).await;
    let persisted = invoke(controller, &["status"]).await.unwrap();
    assert_eq!(persisted[ID]["desiredRunning"], false);
    assert_eq!(persisted[ID]["generation"], stopped[ID]["generation"]);
    ui_action("reactivate", 202).await;
    let started = invoke(controller, &["status"]).await.unwrap();
    assert_eq!(
        started[ID]["generation"].as_u64().unwrap(),
        stopped[ID]["generation"].as_u64().unwrap() + 1
    );
    invoke(controller, &["start", ID]).await.unwrap();
    assert_eq!(invoke(controller, &["status"]).await.unwrap(), started);
}

/// The stopped manager's journal entry for `ID`.
fn stored() -> Slot {
    Journal::open(Path::new(ROOT))
        .unwrap()
        .slot(ID)
        .unwrap()
        .clone()
}

/// Rewrite the stopped manager's journal entry for `ID` and return the entry it replaced.
fn preseed(change: impl FnOnce(&mut Slot)) -> Slot {
    let mut journal = Journal::open(Path::new(ROOT)).unwrap();
    let before = journal.slot(ID).unwrap().clone();
    let mut slot = before.clone();
    change(&mut slot);
    journal.save(ID, slot).unwrap();
    before
}

async fn installation(controller: &Path) -> Value {
    invoke(controller, &["status"]).await.unwrap()[ID].clone()
}

/// The process ID that the running fixture app recorded when it started.
fn app_process() -> Vec<u8> {
    fs::read(storage::directory(UID).join("data/app-pid")).unwrap()
}

/// Record `slot` as an interrupted removal or purge of a stopped installation whose claimed
/// storage still holds data. Returns the path of a retained data file.
fn reserve_interrupted(journal: &mut Journal, id: &str, slot: Slot) -> PathBuf {
    storage::claim(id, &slot).unwrap();
    let data = storage::directory(slot.uid).join("data");
    fs::create_dir(&data).unwrap();
    chown(&data, Some(slot.uid), Some(slot.uid)).unwrap();
    fs::set_permissions(&data, fs::Permissions::from_mode(0o700)).unwrap();
    let retained = data.join("retained");
    fs::write(&retained, b"retained data").unwrap();
    journal
        .save(
            id,
            Slot {
                storage_claimed: Some(true),
                ..slot
            },
        )
        .unwrap();
    retained
}

/// Boot from journal entries that interrupted transitions leave behind, then refuse releases
/// that cannot become the running generation. The manager is stopped before and after, with
/// 1.0.0 committed. `staged` is a working candidate and `incompatible` declares data that the
/// installation never wrote. Returns the retained previous release to restore afterwards.
async fn check_interrupted_transitions(
    controller: &Path,
    config: &Path,
    token: &Path,
    staged: &Release,
    incompatible: &Release,
) -> Option<Release> {
    let last_grants = Path::new(SOCKET).with_file_name("last-grants-generation");

    // An update stopped after it reserved the next generation, before it could publish new
    // grants. The boot fences that generation and restarts the committed release with the
    // grants that were already approved.
    let approved = fs::read(&last_grants).unwrap();
    let committed = preseed(|slot| {
        slot.generation += 1;
        slot.candidate = Some(staged.clone());
        slot.pending_fence = true;
        slot.recovery_required = true;
        slot.grants_uncertain = Some(false);
    });
    assert!(!committed.pending_fence && !committed.recovery_required);
    assert!(committed.desired_running);
    let mut manager = mount_manager(controller, config, token, BootState::Running).await;
    let state = installation(controller).await;
    assert_eq!(state["active"], "1.0.0");
    assert_eq!(state["candidate"], staged.version);
    assert_eq!(state["generation"], committed.generation + 2);
    assert_eq!(fs::read(&last_grants).unwrap(), approved);

    // A candidate that stays alive but never reports the supported protocol reaches its startup
    // limit, and the committed release starts again. Only the candidate's start consumes the
    // marker, so the restarted release reports the supported protocol.
    let marker = storage::directory(UID).join("data/fixture-never-ready");
    fs::write(&marker, []).unwrap();
    let error = invoke(controller, &["activate", ID]).await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("timed out. Previous release restarted with previously approved grants"),
        "{error}"
    );
    assert!(!marker.exists(), "the candidate did not start");
    let state = installation(controller).await;
    assert_eq!(state["active"], "1.0.0");
    assert_eq!(state["candidate"], staged.version);
    assert_eq!(state["running"], true);
    assert_eq!(state["recoveryRequired"], false);
    assert_eq!(state["generation"], committed.generation + 4);
    halt(&mut manager).await;

    // An activation stopped after it may have published new grants. The boot restarts the
    // committed release with an empty grant set until an administrator approves it again.
    let committed = preseed(|slot| {
        slot.generation += 1;
        slot.pending_fence = true;
        slot.recovery_required = true;
        slot.grants_uncertain = Some(true);
    });
    let mut manager = mount_manager(controller, config, token, BootState::Running).await;
    let restarted = committed.generation + 2;
    let state = installation(controller).await;
    assert_eq!(state["active"], "1.0.0");
    assert_eq!(state["generation"], restarted);
    assert_eq!(
        fs::read_to_string(&last_grants).unwrap(),
        restarted.to_string()
    );
    halt(&mut manager).await;
    let recovered = stored();
    assert_eq!(recovered.grants_uncertain, None);
    assert!(!recovered.recovery_required && !recovered.pending_fence);

    // A removal stopped after it reserved the installation. The authority cannot confirm the
    // removal at boot, so the installation stays reserved and needs recovery. Starting it
    // cancels the removal and runs the committed release again.
    let refusal = Path::new(SOCKET).with_file_name(REFUSE_REMOVAL);
    fs::write(&refusal, []).unwrap();
    let committed = preseed(|slot| {
        slot.removal = Removal::Removing;
        slot.desired_running = false;
        // Removal reserves only installations without unresolved provider dependencies.
        slot.provider_dependencies_unknown = false;
    });
    let mut manager = mount_manager(controller, config, token, BootState::Recovery).await;
    assert_eq!(installation(controller).await["removal"], "removing");
    fs::remove_file(&refusal).unwrap();
    invoke(controller, &["start", ID]).await.unwrap();
    let state = installation(controller).await;
    assert_eq!(state["removal"], "installed");
    assert_eq!(state["running"], true);
    assert_eq!(state["desiredRunning"], true);
    assert_eq!(state["active"], "1.0.0");
    assert_eq!(state["generation"], committed.generation + 1);
    halt(&mut manager).await;

    // A release that declares data the installation never wrote, without a migration that
    // creates it, cannot open the stored data. Activating it, or rolling back to it, is refused
    // before the fence: the running generation, its process and the journal stay unchanged.
    let committed = preseed(|slot| {
        slot.candidate = Some(incompatible.clone());
        slot.previous = Some(incompatible.clone());
        slot.approve(
            incompatible,
            vec![serde_json::from_value(monitoring_grant()).unwrap()],
        );
    });
    let mut manager = mount_manager(controller, config, token, BootState::Running).await;
    let before = installation(controller).await;
    let process = app_process();
    let stored_approval = || -> Value {
        let journal = fs::read(Path::new(ROOT).join("journal.json")).unwrap();
        let state: Value = serde_json::from_slice(&journal).unwrap();
        state["installations"][ID]["approvals"][&incompatible.archive_sha256].clone()
    };
    let approval = stored_approval();
    assert_eq!(approval["grants"], json!([monitoring_grant()]));
    // Root's empty set is refused before the fence, so the release keeps the approval it had.
    let error = invoke(controller, &["activate", ID]).await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("Declared data versions require migration or recovery"),
        "{error}"
    );
    assert_eq!(stored_approval(), approval);
    let view = manager_catalog(None, 200).await;
    let row = catalog_row(&view);
    let rollback = lifecycle_input("rollback", row, Some(&row["previous"]));
    assert_eq!(rollback["target"]["version"], incompatible.version);
    assert_eq!(
        manager_catalog(Some(&rollback), 202).await["status"],
        "pending"
    );
    let refused = ui_outcome(&rollback).await;
    assert_eq!(refused["status"], "failed", "{refused}");
    assert_eq!(refused["error"], "incompatibleData", "{refused}");
    assert_eq!(installation(controller).await, before);
    assert_eq!(app_process(), process);
    halt(&mut manager).await;
    committed.previous
}

pub(super) async fn exercise() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let controller = PathBuf::from(std::env::var_os("RENTNERPROXY_TEST_CONTROLLER").unwrap());
    let executable = PathBuf::from(std::env::var_os("RENTNERPROXY_TEST_APP").unwrap());
    let fixed_directory = |parent: &Path, name: &str| {
        tempfile::Builder::new()
            .prefix(name)
            .rand_bytes(0)
            .tempdir_in(parent)
            .unwrap()
    };
    let run_guard = fixed_directory(Path::new("/run"), "rentnerproxy");
    let run = run_guard.path();
    fs::set_permissions(run, fs::Permissions::from_mode(0o755)).unwrap();
    let state = Path::new(ROOT).parent().unwrap();
    let journal_guard = fixed_directory(state, "app-manager");
    fs::set_permissions(journal_guard.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let storage = state.join("apps");
    assert_eq!(
        fs::symlink_metadata(&storage).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
    struct AppStorage(PathBuf);
    impl Drop for AppStorage {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    // Only this isolated fixture can create the previously absent storage tree.
    let _storage_guard = AppStorage(storage);
    assert!(
        Process::new(&controller)
            .args(["--app-backup", "empty"])
            .env(
                "RENTNERPROXY_APP_INSTALLER_CONFIG",
                state.join("missing-installer.json")
            )
            .status()
            .await
            .unwrap()
            .success()
    );
    let api = run.join("app-api");
    fs::create_dir(&api).unwrap();
    chown(&api, Some(10002), Some(10002)).unwrap();
    fs::set_permissions(&api, fs::Permissions::from_mode(0o700)).unwrap();
    let mut gateway = Process::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "app_manager::tests::lifecycle::authority_fixture",
            "--nocapture",
        ])
        .uid(10002)
        .gid(10002)
        .env(
            GRANT_LOG,
            Path::new(SOCKET).with_file_name("grant-log.jsonl"),
        )
        .stdout(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    timeout(Duration::from_secs(5), async {
        while !Path::new(SOCKET).exists() {
            assert!(gateway.try_wait().unwrap().is_none());
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let temp = tempfile::tempdir_in("/run").unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o711)).unwrap();
    let token = temp.path().join("token");
    fs::write(&token, b"local-lifecycle-fixture").unwrap();
    fs::set_permissions(&token, fs::Permissions::from_mode(0o400)).unwrap();
    let (catalog, config, packages) = CatalogServer::start(temp.path(), &executable);
    let release = |p: &StagedPackage| Release {
        version: p.manifest["version"].as_str().unwrap().into(),
        archive_sha256: p.archive_sha256.clone(),
        manifest_sha256: p.manifest_sha256.clone(),
        catalog_revision: p.catalog_revision,
    };
    let mut journal = Journal::open(Path::new(ROOT)).unwrap();
    let interrupted = Slot {
        app_id: "example.probe".into(),
        uid: UID + 2,
        generation: 1,
        authority_recorded: Some(true),
        candidate: Some(release(&packages[0])),
        pending_fence: true,
        ..Default::default()
    };
    journal.save(INTERRUPTED, interrupted.clone()).unwrap();
    assert!(!storage::reconcile_first_claim(INTERRUPTED, &interrupted).unwrap());
    let acknowledged = Slot {
        storage_claimed: Some(true),
        ..interrupted.clone()
    };
    assert!(storage::reconcile_first_claim(INTERRUPTED, &acknowledged).is_err());
    storage::claim(INTERRUPTED, &interrupted).unwrap();
    let reservation = storage::directory(interrupted.uid);
    let first_data = reservation.join("data");
    fs::create_dir(&first_data).unwrap();
    chown(&first_data, Some(interrupted.uid), Some(interrupted.uid)).unwrap();
    fs::set_permissions(&first_data, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(storage::reconcile_first_claim(INTERRUPTED, &interrupted).unwrap());
    fs::remove_dir(first_data).unwrap();
    let lock = reservation.join(".provision.lock");
    fs::write(&lock, []).unwrap();
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();
    let unexpected = reservation.join("unexpected");
    fs::write(&unexpected, "retain").unwrap();
    journal
        .save(
            UNCLAIMED,
            Slot {
                app_id: "example.probe".into(),
                uid: UID + 1,
                candidate: Some(release(&packages[0])),
                storage_claimed: Some(false),
                ..Default::default()
            },
        )
        .unwrap();
    journal
        .save(
            ID,
            Slot {
                app_id: "example.probe".into(),
                uid: UID,
                candidate: Some(release(&packages[1])),
                active: Some(release(&packages[0])),
                desired_running: true,
                ..Default::default()
            },
        )
        .unwrap();
    drop(journal);
    let installer_lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(temp.path().join("store/.install.lock"))
        .unwrap();
    installer_lock.lock().unwrap();
    let release_lock = async {
        while UnixStream::connect("/run/rentnerproxy/app-manager/control.sock")
            .await
            .is_err()
        {
            sleep(Duration::from_millis(20)).await;
        }
        // Outlast the installer's own 500 ms lock wait during boot.
        sleep(Duration::from_millis(1300)).await;
        drop(installer_lock);
    };
    let (mut manager, ()) = tokio::join!(
        mount_manager(&controller, &config, &token, BootState::Running),
        release_lock
    );
    assert!(invoke(&controller, &["activate", UNCLAIMED]).await.is_err());
    invoke(&controller, &["remove", UNCLAIMED]).await.unwrap();
    assert!(!super::super::storage::directory(UID + 1).exists());
    assert!(invoke(&controller, &["remove", INTERRUPTED]).await.is_err());
    assert_eq!(fs::read(&unexpected).unwrap(), b"retain");
    fs::remove_file(unexpected).unwrap();
    invoke(&controller, &["remove", INTERRUPTED]).await.unwrap();
    assert!(!reservation.exists());
    let states = invoke(&controller, &["status"]).await.unwrap();
    assert_eq!(states[ID]["active"], "1.0.0");
    assert_eq!(states[ID]["candidate"], "1.1.0");
    assert_eq!(states[ID]["running"], true);
    check_control_boundary(&controller, temp.path()).await;
    let states = invoke(&controller, &["status"]).await.unwrap();
    assert_eq!(states[ID]["active"], "1.1.0");
    assert_eq!(states[ID]["previous"], "1.0.0");
    let note = storage::directory(UID).join("data/signed-update-fixture");
    fs::write(&note, b"data before update").unwrap();
    chown(&note, Some(UID), Some(UID)).unwrap();
    ui_signed_switch(&controller, &release(&packages[0]), &release(&packages[1])).await;
    check_revocation(&controller).await;
    let updated = installation(&controller).await;
    halt(&mut manager).await;
    drop(catalog);
    let mut manager = mount_manager(&controller, &config, &token, BootState::Running).await;
    let restored = invoke(&controller, &["status"]).await.unwrap();
    assert_eq!(restored[ID]["active"], updated["active"]);
    assert_eq!(restored[ID]["previous"], updated["previous"]);
    assert_eq!(
        restored[ID]["generation"].as_u64().unwrap(),
        updated["generation"].as_u64().unwrap() + 1
    );
    // The boot published the committed release's approval for its new generation.
    assert_eq!(
        last_grants(),
        json!({
            "generation": restored[ID]["generation"],
            "activated": false,
            "grants": [monitoring_grant()],
        })
    );
    assert_eq!(fs::read(&note).unwrap(), b"data before update");
    assert_provider_invocation().await;
    check_approved_restarts(&controller, &config, &token, &mut manager).await;
    invoke(&controller, &["rollback", ID]).await.unwrap();
    check_process_recovery(&controller, &config, &token, &mut manager).await;
    halt(&mut manager).await;
    verify_uid_stopped(UID).unwrap();
    backup_files(&controller, &config, &token, temp.path()).await;
    let archive = temp
        .path()
        .join("store/archives")
        .join(&packages[0].archive_sha256);
    let saved = temp.path().join("offline-archive");
    fs::rename(&archive, &saved).unwrap();
    let last_grants = Path::new(SOCKET).with_file_name("last-grants-generation");
    let before_grants = fs::read(&last_grants).unwrap();
    let mut manager = mount_manager(&controller, &config, &token, BootState::Recovery).await;
    fs::rename(saved, archive).unwrap();
    invoke(&controller, &["start", ID]).await.unwrap();
    assert_eq!(fs::read(&last_grants).unwrap(), before_grants);
    halt(&mut manager).await;
    let previous = check_interrupted_transitions(
        &controller,
        &config,
        &token,
        &release(&packages[1]),
        &release(&packages[3]),
    )
    .await;
    let mut journal = Journal::open(Path::new(ROOT)).unwrap();
    let mut slot = journal.slot(ID).unwrap().clone();
    assert!(!slot.pending_fence && slot.desired_running);
    slot.candidate = Some(release(&packages[2]));
    slot.previous = previous;
    journal.save(ID, slot).unwrap();
    drop(journal);
    let mut manager = mount_manager(&controller, &config, &token, BootState::Running).await;
    let before = invoke(&controller, &["status"]).await.unwrap()[ID]["generation"]
        .as_u64()
        .unwrap();
    let error = invoke(&controller, &["activate", ID]).await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("Previous release restarted with previously approved grants"),
        "{error}"
    );
    let states = invoke(&controller, &["status"]).await.unwrap();
    assert_eq!(states[ID]["active"], "1.0.0");
    assert_eq!(states[ID]["candidate"], "1.1.0-rc.1");
    assert_eq!(states[ID]["running"], true);
    assert_eq!(states[ID]["generation"], before + 2);
    halt(&mut manager).await;
    let capture = || {
        let mut command = Process::new(&controller);
        command
            .args(["--app-backup", "capture"])
            .env("RENTNERPROXY_APP_INSTALLER_CONFIG", &config);
        command
    };
    crate::app_install::tests::revoke_lifecycle_release(&config, "1.1.0");
    assert!(!capture().output().await.unwrap().status.success());
    let mut manager = mount_manager(&controller, &config, &token, BootState::Running).await;
    let before = invoke(&controller, &["status"]).await.unwrap()[ID].clone();
    assert_eq!(before["previous"], "1.1.0");
    assert!(
        invoke(&controller, &["discard", ID, "active"])
            .await
            .is_err()
    );
    invoke(&controller, &["discard", ID, "previous"])
        .await
        .unwrap();
    invoke(&controller, &["discard", ID, "candidate"])
        .await
        .unwrap();
    let status = invoke(&controller, &["status"]).await.unwrap();
    assert_eq!(status[ID]["generation"], before["generation"]);
    assert_eq!(status[ID]["active"], before["active"]);
    assert_eq!(status[ID]["running"], true);
    halt(&mut manager).await;
    let backup = capture().output().await.unwrap();
    assert!(
        backup.status.success(),
        "{}",
        String::from_utf8_lossy(&backup.stderr)
    );
    let snapshot: Value = serde_json::from_slice(&backup.stdout).unwrap();
    assert!(snapshot["installations"][ID]["previous"].is_null());
    assert!(snapshot["installations"][ID]["candidate"].is_null());
    crate::app_install::tests::revoke_lifecycle_release(&config, "1.0.0");
    assert!(!capture().output().await.unwrap().status.success());
    // Declared provider profiles conservatively block removal until an operator
    // resolution exists. Clear that marker offline so the removal path stays covered.
    let mut journal = Journal::open(Path::new(ROOT)).unwrap();
    let mut slot = journal.slot(ID).unwrap().clone();
    assert!(slot.provider_dependencies_unknown);
    slot.provider_dependencies_unknown = false;
    journal.save(ID, slot).unwrap();
    // A removal and a purge that stopped after they reserved their installations finish at the
    // next boot. The removal keeps the installation's data and the purge erases it.
    let removed_data = reserve_interrupted(
        &mut journal,
        RESUMED_REMOVAL,
        Slot {
            app_id: "example.probe".into(),
            uid: UID + 3,
            generation: 1,
            authority_recorded: Some(true),
            active: Some(release(&packages[0])),
            desired_running: false,
            pending_fence: true,
            removal: Removal::Removing,
            ..Default::default()
        },
    );
    let purged_data = reserve_interrupted(
        &mut journal,
        RESUMED_PURGE,
        Slot {
            app_id: "example.probe".into(),
            uid: UID + 4,
            generation: 1,
            authority_recorded: Some(true),
            removed_release: Some((&release(&packages[0])).into()),
            removal: Removal::Purging,
            ..Default::default()
        },
    );
    drop(journal);
    let mut manager = mount_manager(&controller, &config, &token, BootState::Recovery).await;
    let states = invoke(&controller, &["status"]).await.unwrap();
    assert_eq!(states[RESUMED_REMOVAL]["removal"], "removed", "{states}");
    assert!(states[RESUMED_REMOVAL]["active"].is_null());
    assert_eq!(fs::read(&removed_data).unwrap(), b"retained data");
    assert_eq!(states[RESUMED_PURGE]["removal"], "purged", "{states}");
    assert!(!purged_data.exists());
    assert!(!storage::directory(UID + 4).exists());
    ui_action("purge", 409).await;
    ui_action("uninstall", 202).await;
    let data = super::super::storage::directory(UID);
    assert!(data.join("data/app-pid").is_file());
    ui_action("purge", 202).await;
    assert!(!data.exists());
    halt(&mut manager).await;
    verify_uid_stopped(UID).unwrap();
    gateway.kill().await.unwrap();
}
