use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    os::unix::{
        fs::{FileExt, MetadataExt, PermissionsExt, chown},
        net::UnixStream,
        process::CommandExt,
    },
    path::Path,
    process::{Child, Command, Stdio},
    thread::sleep,
    time::{Duration, Instant},
};

use marketplace_app_catalog::bootstrap_catalog;
use marketplace_artifacts::{digest, file_identity};
use serde_json::{Value, json};

use super::{Installer, PIN, PackageSource, keys, now, refresh};

#[path = "greeting/publication.rs"]
mod publication;
use publication::{Candidate, download};

const ID: &str = "rentnerproxy.greeting";
const FIRST_VERSION: &str = "1.0.0";
const SECOND_VERSION: &str = "1.1.0";
const INSTALLATION: &str = "greeting-fixture";
const UID: u32 = 20_123;
const APP_CREDENTIAL: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CORE_CREDENTIAL: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn flip_archive_byte(path: &Path) {
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    let mut byte = [0];
    file.read_exact_at(&mut byte, 0).unwrap();
    byte[0] ^= 0x80;
    file.write_all_at(&byte, 0).unwrap();
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
    let request = format!(
        "POST /app/v1/api/{name} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
        Authorization: Bearer {APP_CREDENTIAL}\r\nX-App-Installation: {INSTALLATION}\r\n\
        X-App-Generation: {generation}\r\nIdempotency-Key: {key}\r\n\
        Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    client.write_all(request.as_bytes()).unwrap();
    // A rejection may close the socket before consuming the request body.
    // Read the response by its advertised length, without waiting for EOF.
    let mut response = BufReader::new(client.take(8192));
    let mut line = String::new();
    response.read_line(&mut line).unwrap();
    let status = line
        .split_ascii_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let mut length = None;
    loop {
        line.clear();
        assert!(
            response.read_line(&mut line).unwrap() > 0,
            "Incomplete {name} response"
        );
        if line == "\r\n" {
            break;
        }
        if let Some((key, value)) = line.split_once(':')
            && key.eq_ignore_ascii_case("content-length")
        {
            length = Some(value.trim().parse::<usize>().unwrap());
        }
    }
    let mut body = vec![0; length.filter(|length| *length <= 8192).unwrap()];
    response.read_exact(&mut body).unwrap();
    (status, serde_json::from_slice(&body).unwrap())
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
    let first = Candidate::seal(
        &fixture.join(FIRST_VERSION),
        &root.join("v1"),
        FIRST_VERSION,
        "101",
    );
    let second = Candidate::seal(
        &fixture.join(SECOND_VERSION),
        &root.join("v2"),
        SECOND_VERSION,
        "102",
    );
    let releases = root.join("releases");
    fs::create_dir(&releases).unwrap();
    let mut files = bootstrap_catalog(PIN, &keys(), now()).unwrap();
    refresh(&installer, &files, now()).unwrap();
    first.publish(&mut files, &releases);
    let first_snapshot = files.clone();
    let trusted = refresh(&installer, &first_snapshot, now()).unwrap();
    let first_stage = installer
        .prepare(
            &trusted,
            ID,
            FIRST_VERSION,
            PackageSource::Catalog(None),
            |asset| download(&releases, asset),
        )
        .unwrap();
    assert_eq!(first_stage.catalog_revision, 2);
    let first_archive = first.archive(native);
    let first_size = fs::metadata(&first_archive).unwrap().len();
    assert_eq!(
        first_stage.archive_sha256,
        file_identity(&first_archive, first_size).unwrap().sha256
    );
    let unavailable = installer
        .prepare::<std::io::Empty>(
            &trusted,
            ID,
            SECOND_VERSION,
            PackageSource::Catalog(None),
            |_| panic!("Unapproved version reached the download boundary"),
        )
        .unwrap_err();
    assert!(
        unavailable
            .to_string()
            .contains("revoked, missing, or unavailable")
    );
    assert!(second.verify(&first.approval).is_err());

    let second_archive = second.archive(native);
    flip_archive_byte(&second_archive);
    assert!(second.verify(&second.approval).is_err());
    flip_archive_byte(&second_archive);
    second.publish(&mut files, &releases);
    let trusted = refresh(&installer, &files, now()).unwrap();
    let distributed = releases
        .join(format!("{ID}-v{SECOND_VERSION}"))
        .join(second_archive.file_name().unwrap());
    let size = fs::metadata(&second_archive).unwrap().len();
    let approved = file_identity(&second_archive, size).unwrap();
    assert_ne!(approved.sha256, first_stage.archive_sha256);
    flip_archive_byte(&distributed);
    let corrupt = installer
        .prepare(
            &trusted,
            ID,
            SECOND_VERSION,
            PackageSource::Catalog(None),
            |asset| download(&releases, asset),
        )
        .unwrap_err();
    assert_eq!(
        corrupt.to_string(),
        "Compressed package differs from its signed identity"
    );
    for kind in ["archives", "packages"] {
        assert!(!store.join(kind).join(&approved.sha256).exists());
    }
    flip_archive_byte(&distributed);
    let second_stage = installer
        .prepare(
            &trusted,
            ID,
            SECOND_VERSION,
            PackageSource::Catalog(None),
            |asset| download(&releases, asset),
        )
        .unwrap();
    assert_eq!(second_stage.archive_sha256, approved.sha256);
    assert_eq!(second_stage.catalog_revision, 3);
    assert_eq!(
        file_identity(
            &store.join("archives").join(&second_stage.archive_sha256),
            size
        )
        .unwrap(),
        approved
    );

    let reopened = Installer::open(&config).unwrap();
    assert!(refresh(&reopened, &first_snapshot, now()).is_err());
    for staged in [&first_stage, &second_stage] {
        let recovered = reopened
            .recover(
                ID,
                staged.manifest["version"].as_str().unwrap(),
                &staged.archive_sha256,
            )
            .unwrap();
        assert_eq!(recovered.directory, staged.directory);
    }
    for path in [
        "ui/index.html",
        "ui/app.js",
        "ui/app.css",
        "api/openapi.json",
    ] {
        assert_eq!(
            fs::read(second_stage.directory.join(path)).unwrap(),
            fs::read(fixture.join(SECOND_VERSION).join(native).join(path)).unwrap()
        );
    }

    let data = root.join("data");
    fs::create_dir(&data).unwrap();
    fs::set_permissions(&data, fs::Permissions::from_mode(0o700)).unwrap();
    chown(&data, Some(UID), Some(UID)).unwrap();
    let socket = root.join("app");
    fs::create_dir(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o700)).unwrap();
    chown(&socket, Some(UID), Some(UID)).unwrap();
    let first_socket = socket.join("first.sock");
    let app = start(
        &first_stage.directory.join("bin/app"),
        &data,
        &first_socket,
        1,
    );
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
    let _app = start(
        &second_stage.directory.join("bin/app"),
        &data,
        &second_socket,
        2,
    );
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
    let release_evidence = [&first_stage, &second_stage].map(|staged| {
        json!({
            "version": staged.manifest["version"], "catalogRevision": staged.catalog_revision,
            "archiveSha256": staged.archive_sha256, "manifestSha256": staged.manifest_sha256,
        })
    });
    println!(
        "GREETING_EVIDENCE {}",
        json!({
            "target": native, "revision": second_stage.manifest["source"]["commit"],
            "releases": release_evidence,
            "uiBundleSha256": digest(&fs::read(second_stage.directory.join("ui/app.js")).unwrap()),
            "checks": ["approval-binding", "corrupt-handoff-rejection", "corrupt-download-rejection",
                "unapproved-version-rejection", "catalog-rollback-rejection", "offline-recover",
                "packaged-ui", "generation-rejection", "file-persists-through-update"],
        })
    );
}
