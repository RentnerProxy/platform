use super::super::*;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode, body::Incoming, service::service_fn};
use hyper_util::rt::TokioIo;
use std::{
    convert::Infallible,
    fs,
    os::unix::fs::{PermissionsExt, chown},
    process::Stdio,
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    process::{Child, Command as Process},
};

const ID: &str = "fixture-install";
const UID: u32 = 59553;
const ROOT: &str = "/var/lib/rentnerproxy/app-manager";
const SOCKET: &str = "/run/rentnerproxy/app-api/web.sock";

async fn authority(
    request: Request<Incoming>,
    generations: Arc<Mutex<BTreeMap<u64, bool>>>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let path = request.uri().path().to_owned();
    assert_eq!(
        request.headers()["authorization"],
        "Bearer local-lifecycle-fixture"
    );
    let body = request.into_body().collect().await.unwrap().to_bytes();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["identity"]["installationId"], ID);
    assert_eq!(value["identity"]["uid"], UID);
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
    match action {
        "register" => {
            assert!(states.is_empty());
            states.insert(generation, false);
        }
        "grants" => {
            assert_eq!(states.get(&generation), Some(&false));
            assert_eq!(value["grants"], json!([]));
        }
        "activate" => {
            assert_eq!(states.insert(generation, true), Some(false));
        }
        "renew" => assert_eq!(states.get(&generation), Some(&true)),
        "retire" => {
            states.remove(&generation);
        }
        "workers-stopped" | "purge-data" => assert!(states.is_empty()),
        "removable" => (),
        _ => panic!("unexpected private action {action}"),
    }
    Ok(Response::builder()
        .status(StatusCode::NO_CONTENT)
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

async fn mount_manager(controller: &Path, config: &Path, token: &Path) -> Child {
    let mut child = Process::new(controller)
        .arg("--app-manager")
        .arg(config)
        .env(crate::config::CONTROLLER_TOKEN_FILE_ENV, token)
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    timeout(Duration::from_secs(20), async {
        loop {
            assert!(child.try_wait().unwrap().is_none());
            if invoke(controller, &["status"]).await.is_ok() {
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

async fn backup_files(controller: &Path, config: &Path, temporary: &Path) {
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
    fs::remove_dir_all(&data).unwrap();
    assert!(
        command("restore")
            .arg(&snapshot)
            .status()
            .await
            .unwrap()
            .success()
    );
    assert_eq!(fs::read(&note).unwrap(), b"offline fixture");
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
    fs::write(&grants, "[]").unwrap();
    invoke(controller, &["activate", ID, path]).await.unwrap();
}

async fn check_process_recovery(controller: &Path) {
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
    invoke(controller, &["start", ID]).await.unwrap();
    invoke(controller, &["stop", ID]).await.unwrap();
    let stopped = invoke(controller, &["status"]).await.unwrap();
    assert_eq!(stopped[ID]["running"], false);
    assert_eq!(stopped[ID]["desiredRunning"], false);
    invoke(controller, &["start", ID]).await.unwrap();
    let started = invoke(controller, &["status"]).await.unwrap();
    invoke(controller, &["start", ID]).await.unwrap();
    assert_eq!(invoke(controller, &["status"]).await.unwrap(), started);
}

pub(super) async fn exercise() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let controller = PathBuf::from(std::env::var_os("RENTNERPROXY_TEST_CONTROLLER").unwrap());
    let executable = PathBuf::from(std::env::var_os("RENTNERPROXY_TEST_APP").unwrap());
    assert!(!Path::new(ROOT).exists() && !Path::new(SOCKET).exists());
    let run = Path::new("/run/rentnerproxy");
    fs::create_dir_all(run).unwrap();
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
    let (config, packages) =
        crate::app_install::tests::lifecycle_packages(temp.path(), &executable);
    let release = |p: &StagedPackage| Release {
        version: p.manifest["version"].as_str().unwrap().into(),
        archive_sha256: p.archive_sha256.clone(),
        manifest_sha256: p.manifest_sha256.clone(),
        catalog_revision: p.catalog_revision,
    };
    let mut journal = Journal::open(Path::new(ROOT)).unwrap();
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
    let mut manager = mount_manager(&controller, &config, &token).await;
    let states = invoke(&controller, &["status"]).await.unwrap();
    assert_eq!(states[ID]["active"], "1.0.0");
    assert_eq!(states[ID]["candidate"], "1.1.0");
    assert_eq!(states[ID]["running"], true);
    check_control_boundary(&controller, temp.path()).await;
    let states = invoke(&controller, &["status"]).await.unwrap();
    assert_eq!(states[ID]["active"], "1.1.0");
    assert_eq!(states[ID]["previous"], "1.0.0");
    invoke(&controller, &["rollback", ID]).await.unwrap();
    check_process_recovery(&controller).await;
    halt(&mut manager).await;
    verify_uid_stopped(UID).unwrap();
    backup_files(&controller, &config, temp.path()).await;
    let mut journal = Journal::open(Path::new(ROOT)).unwrap();
    let mut slot = journal.slot(ID).unwrap().clone();
    assert!(!slot.pending_fence && slot.desired_running);
    slot.candidate = Some(release(&packages[2]));
    journal.save(ID, slot).unwrap();
    drop(journal);
    let mut manager = mount_manager(&controller, &config, &token).await;
    let before = invoke(&controller, &["status"]).await.unwrap()[ID]["generation"]
        .as_u64()
        .unwrap();
    assert!(invoke(&controller, &["activate", ID]).await.is_err());
    let states = invoke(&controller, &["status"]).await.unwrap();
    assert_eq!(states[ID]["active"], "1.0.0");
    assert_eq!(states[ID]["candidate"], "1.2.0");
    assert_eq!(states[ID]["running"], true);
    assert_eq!(states[ID]["generation"], before + 2);
    invoke(&controller, &["remove", ID]).await.unwrap();
    let data = super::super::storage::directory(UID);
    assert!(data.join("data/app-pid").is_file());
    invoke(&controller, &["purge", ID]).await.unwrap();
    assert!(!data.exists());
    halt(&mut manager).await;
    verify_uid_stopped(UID).unwrap();
    gateway.kill().await.unwrap();
}
