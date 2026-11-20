use std::{
    fs,
    io::{Read, Write},
    os::unix::{
        fs::{MetadataExt, PermissionsExt, chown},
        net::UnixStream,
        process::CommandExt,
    },
    path::Path,
    process::{Child, Command, Stdio},
    thread::sleep,
    time::{Duration, Instant},
};

use marketplace_app_catalog::bootstrap_catalog;
use marketplace_artifacts::digest;
use serde_json::{Value, json};

use super::{Files, Installer, PIN, keys, now, pack_fixture, refresh, update};

const ID: &str = "rentnerproxy.greeting";
const VERSION: &str = "1.0.0";
const INSTALLATION: &str = "greeting-fixture";
const UID: u32 = 20_123;
const APP_CREDENTIAL: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CORE_CREDENTIAL: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const PACKAGE_FILES: [&str; 7] = [
    "app.json",
    "bin/app",
    "LICENSE",
    "api/openapi.json",
    "ui/index.html",
    "ui/app.js",
    "ui/app.css",
];

fn package(package_directory: &Path, work: &Path) -> (Value, Vec<u8>) {
    fs::create_dir(work).unwrap();
    let archive = pack_fixture(
        work,
        PACKAGE_FILES.into_iter().map(|path| {
            let mode = if path == "bin/app" { 0o755 } else { 0o644 };
            (path, mode, fs::read(package_directory.join(path)).unwrap())
        }),
    );
    let raw = fs::read(package_directory.join("app.json")).unwrap();
    let manifest: Value = serde_json::from_slice(&raw).unwrap();
    let fixture_sidecar = json!({"sizeBytes":1,"sha256":"a".repeat(64)});
    let package = json!({
        "manifest": manifest,
        "archive": {"sha256": digest(&archive), "sizeBytes": archive.len()},
        "manifestSha256": digest(&raw),
        "sbom": fixture_sidecar,
        "provenance": fixture_sidecar,
    });
    (package, archive)
}

struct AppProcess(Child);

impl Drop for AppProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start(executable: &Path, data: &Path, socket: &Path, generation: u64) -> AppProcess {
    let mut child = AppProcess(
        Command::new(executable)
            .uid(UID)
            .gid(UID)
            .current_dir(data)
            .env_clear()
            .env("RENTNERPROXY_APP_BOOTSTRAP_FD", "0")
            .stdin(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut input = child.0.stdin.take().unwrap();
    let bootstrap = json!({
        "formatVersion": 1, "appId": ID, "runtimeProfile": "rentnerproxy-linux-v1",
        "installationId": INSTALLATION, "generation": generation, "appSocket": socket,
        "coreSocket": data.join("core.sock"),
        "appCredential": APP_CREDENTIAL, "coreCredential": CORE_CREDENTIAL,
        "versions": {"appProtocol":"1.0.0","platformApi":"1.0.0","uiBridge":"1.0.0"},
    });
    serde_json::to_writer(&mut input, &bootstrap).unwrap();
    drop(input);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !socket.exists() {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "Greeting exited before readiness"
        );
        assert!(Instant::now() < deadline, "Greeting socket did not bind");
        sleep(Duration::from_millis(20));
    }
    child
}

fn operation(socket: &Path, generation: u64, name: &str, key: &str, body: Value) -> (u16, Value) {
    let mut client = UnixStream::connect(socket).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    client
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let body = body.to_string();
    write!(
        client,
        "POST /app/v1/api/{name} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
        Authorization: Bearer {APP_CREDENTIAL}\r\nX-App-Installation: {INSTALLATION}\r\n\
        X-App-Generation: {generation}\r\nIdempotency-Key: {key}\r\n\
        Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut response = String::new();
    client.take(8192).read_to_string(&mut response).unwrap();
    let (headers, body) = response.split_once("\r\n\r\n").unwrap();
    let status = headers
        .split_ascii_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    (status, serde_json::from_str(body).unwrap())
}

#[test]
#[ignore = "requires root and disposable Linux runtime directories"]
fn privileged_signed_greeting_package() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let fixture = std::env::var_os("RENTNERPROXY_TEST_GREETING_PACKAGES").unwrap();
    let fixture = Path::new(&fixture);
    let work = tempfile::tempdir_in("/run").unwrap();
    let root = work.path();
    fs::set_permissions(root, fs::Permissions::from_mode(0o711)).unwrap();
    let store = root.join("store");
    fs::create_dir(&store).unwrap();
    fs::set_permissions(&store, fs::Permissions::from_mode(0o711)).unwrap();
    let pin = root.join("root.json");
    fs::write(&pin, PIN).unwrap();
    let config = root.join("installer.json");
    fs::write(
        &config,
        serde_json::to_vec(&json!({
            "storeDirectory": store, "pinnedRoot": pin,
            "repositoryUrl":"https://invalid.example/catalog/", "engineCapabilities": [],
        }))
        .unwrap(),
    )
    .unwrap();
    let installer = Installer::open(&config).unwrap();
    let native = if cfg!(target_arch = "x86_64") {
        "linux-amd64"
    } else {
        "linux-arm64"
    };
    let mut packages = Vec::new();
    let mut native_bytes = None;
    for target in ["linux-amd64", "linux-arm64"] {
        let (package, archive) = package(&fixture.join(target), &root.join(target));
        assert_eq!(package["manifest"]["target"], target);
        packages.push(package);
        if target == native {
            native_bytes = Some(archive);
        }
        fs::remove_dir_all(root.join(target)).unwrap();
    }
    let mut files = bootstrap_catalog(PIN, &keys(), now()).unwrap();
    refresh(&installer, &files, now()).unwrap();
    let release = json!({
        "appId": ID, "version": VERSION, "publisher": {"namespace":"rentnerproxy","name":"Fixture"},
        "source": packages[0]["manifest"]["source"], "packages": packages,
    });
    let next = update(
        &files,
        json!({
            "formatVersion": 1, "revision": 2, "releases": [release], "revocations": [],
        }),
        &Files::new(),
    );
    files.extend(next);
    let trusted = refresh(&installer, &files, now()).unwrap();
    let archive = native_bytes.unwrap();
    let staged = installer
        .prepare(&trusted, ID, VERSION, None, |_| Ok(archive.as_slice()))
        .unwrap();
    assert_eq!(staged.archive_sha256, digest(&archive));
    assert_eq!(staged.catalog_revision, 2);
    let installed = installer
        .recover(ID, VERSION, &staged.archive_sha256)
        .unwrap();
    assert_eq!(staged.directory, installed.directory);
    for path in [
        "ui/index.html",
        "ui/app.js",
        "ui/app.css",
        "api/openapi.json",
    ] {
        assert_eq!(
            fs::read(installed.directory.join(path)).unwrap(),
            fs::read(fixture.join(native).join(path)).unwrap()
        );
    }

    let executable = installed.directory.join("bin/app");
    let data = root.join("data");
    fs::create_dir(&data).unwrap();
    fs::set_permissions(&data, fs::Permissions::from_mode(0o700)).unwrap();
    chown(&data, Some(UID), Some(UID)).unwrap();
    let socket = root.join("app");
    fs::create_dir(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o700)).unwrap();
    chown(&socket, Some(UID), Some(UID)).unwrap();
    let first_socket = socket.join("first.sock");
    let app = start(&executable, &data, &first_socket, 1);
    assert_eq!(
        operation(&first_socket, 1, "get-greeting", "read", json!({})),
        (200, json!({"greeting":"Hello from RentnerProxy!"}))
    );
    assert_eq!(
        operation(&first_socket, 2, "get-greeting", "read", json!({})).0,
        403
    );
    let greeting = json!({"greeting":"Gude from the signed fixture!"});
    assert_eq!(
        operation(&first_socket, 1, "save-greeting", "write", greeting.clone()),
        (200, greeting.clone())
    );
    let metadata = fs::metadata(data.join("greeting.json")).unwrap();
    assert_eq!(metadata.mode() & 0o777, 0o600);
    assert_eq!(metadata.uid(), UID);
    drop(app);
    let second_socket = socket.join("second.sock");
    let _app = start(&executable, &data, &second_socket, 2);
    assert_eq!(
        operation(
            &second_socket,
            2,
            "get-greeting",
            "after-restart",
            json!({})
        ),
        (200, greeting)
    );
    println!(
        "GREETING_EVIDENCE {}",
        json!({
            "target": native, "catalogRevision": staged.catalog_revision,
            "revision": staged.manifest["source"]["commit"],
            "archiveSha256": staged.archive_sha256, "manifestSha256": staged.manifest_sha256,
            "uiBundleSha256": digest(&fs::read(installed.directory.join("ui/app.js")).unwrap()),
            "checks": ["signed-stage", "offline-recover", "packaged-ui", "generation-rejection", "file-persists-after-restart"],
        })
    );
}
