use std::{
    collections::BTreeMap,
    fs, io,
    path::{Path, PathBuf},
};

use ed25519_dalek::{SigningKey, pkcs8::EncodePrivateKey};
use marketplace_app_catalog::{
    SigningKeys, TrustedCatalog, UpdateOptions, bootstrap_catalog, update_catalog,
};
use marketplace_app_pipeline::package::execute;
use marketplace_artifacts::digest;
use rentnerproxy_app_contracts::Contracts;
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

use super::{Config, Installer};

const PIN: &[u8] = include_bytes!("../fixtures/app-install/1.root.json");
const ID: &str = "example.probe";
const VERSION: &str = "1.0.0";
const TARGET: &str = "linux-amd64";
type Files = BTreeMap<String, Vec<u8>>;

fn now() -> OffsetDateTime {
    OffsetDateTime::parse("2026-11-01T12:00:00Z", &Rfc3339).unwrap()
}

fn keys() -> SigningKeys {
    let [targets, snapshot, timestamp] = [3, 4, 5].map(|seed| {
        SigningKey::from_bytes(&[seed; 32])
            .to_pkcs8_pem(Default::default())
            .unwrap()
    });
    SigningKeys::from_pem(&targets, &snapshot, &timestamp).unwrap()
}

fn manager(directory: &Path) -> Installer {
    Installer {
        config: Config {
            store_directory: directory.to_owned(),
            pinned_root: PathBuf::new(),
            repository_url: String::new(),
            engine_capabilities: vec!["caddy.load-balancing.v1".into()],
        },
        target: TARGET,
        pinned_root: PIN.to_vec(),
        contracts: Contracts::new().unwrap(),
    }
}

fn refresh(manager: &Installer, files: &Files, at: OffsetDateTime) -> io::Result<TrustedCatalog> {
    manager.refresh(|name, _| Ok(files.get(name).cloned()), at)
}

fn update(current: &TrustedCatalog, document: Value) -> Files {
    update_catalog(
        current,
        &serde_json::to_vec(&document).unwrap(),
        &keys(),
        UpdateOptions {
            now: now(),
            next_root: None,
            icons: &BTreeMap::new(),
        },
    )
    .unwrap()
}

fn manifest() -> Value {
    json!({
        "formatVersion":1, "id":ID, "version":VERSION, "target":TARGET,
        "source":{"repositoryId":"8001234","commit":"a".repeat(40)},
        "display":{"name":"Probe","summary":"Package validation fixture","license":"MIT"},
        "requires":{"runtimeProfile":"rentnerproxy-linux-v1","platformApi":">=1.0.0 <2.0.0","appProtocol":">=1.0.0 <2.0.0","engineCapabilities":["caddy.load-balancing.v1"]},
        "entrypoint":"bin/app","api":"api/openapi.json","providers":[],"permissions":[],"capabilities":[],
        "resources":{"startupTimeoutMs":10000,"drainTimeoutMs":2000,"memoryMiB":128,"processLimit":16}
    })
}

fn fixture_elf() -> Vec<u8> {
    let mut elf = vec![0; 128];
    elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    for (offset, value) in [(16, 2_u16), (18, 62), (52, 64), (54, 56), (56, 1)] {
        elf[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    for (offset, value) in [(20, 1_u32), (64, 1), (68, 5)] {
        elf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    for (offset, value) in [
        (24, 0x400078_u64),
        (32, 64),
        (80, 0x400000),
        (96, 128),
        (104, 128),
    ] {
        elf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    elf
}

fn package(directory: &Path) -> (Value, Vec<u8>) {
    archive_fixture(directory, manifest(), fixture_elf())
}

fn archive_fixture(directory: &Path, manifest: Value, backend: Vec<u8>) -> (Value, Vec<u8>) {
    let raw = serde_json::to_vec(&manifest).unwrap();
    let mut tar = Vec::new();
    for (path, mode, body) in [
        ("app.json", 0o644, raw.clone()),
        ("bin/app", 0o755, backend),
        ("LICENSE", 0o644, b"MIT".to_vec()),
        (
            "api/openapi.json",
            0o644,
            br#"{"openapi":"3.1.0","info":{"title":"Probe","version":"1"},"paths":{}}"#.to_vec(),
        ),
    ] {
        let mut header = [0; 512];
        header[..path.len()].copy_from_slice(path.as_bytes());
        let octal = |field: &mut [u8], number| {
            let width = field.len() - 1;
            field[..width].copy_from_slice(format!("{number:0width$o}").as_bytes());
        };
        for (start, end, value) in [
            (100, 108, mode),
            (108, 116, 0),
            (116, 124, 0),
            (124, 136, body.len()),
            (136, 148, 0),
        ] {
            octal(&mut header[start..end], value);
        }
        header[148..156].fill(b' ');
        header[156] = b'0';
        header[257..265].copy_from_slice(b"ustar\x0000");
        let checksum = header.iter().map(|&byte| usize::from(byte)).sum();
        octal(&mut header[148..155], checksum);
        tar.extend_from_slice(&header);
        tar.extend_from_slice(&body);
        tar.resize(tar.len().next_multiple_of(512), 0);
    }
    tar.resize(tar.len() + 1024, 0);
    let input = directory.join("fixture.tar");
    let output = directory.join("fixture.tar.zst");
    fs::write(&input, tar).unwrap();
    execute(
        "compress-package",
        json!({"inputPath":input,"outputPath":output}),
    )
    .unwrap();
    let archive = fs::read(output).unwrap();
    let sidecar = json!({"sizeBytes":1,"sha256":"a".repeat(64)});
    let release = json!({"appId":ID,"version":manifest["version"],"source":manifest["source"],
        "publisher":{"namespace":"example","name":"Fixture"},"packages":[{"manifest":manifest,
        "archive":{"sha256":digest(&archive),"sizeBytes":archive.len()},"manifestSha256":digest(&raw),
        "sbom":sidecar,"provenance":sidecar}]});
    (release, archive)
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub(crate) fn lifecycle_packages(
    root: &Path,
    backend: &Path,
) -> (PathBuf, Vec<super::StagedPackage>) {
    use std::os::unix::fs::PermissionsExt;
    let target = if cfg!(target_arch = "aarch64") {
        "linux-arm64"
    } else {
        "linux-amd64"
    };
    let store = root.join("store");
    fs::create_dir(&store).unwrap();
    fs::set_permissions(&store, fs::Permissions::from_mode(0o711)).unwrap();
    let pin = root.join("root.json");
    fs::write(&pin, PIN).unwrap();
    let config = root.join("installer.json");
    fs::write(&config,serde_json::to_vec(&json!({
        "storeDirectory":store, "pinnedRoot":pin,
        "repositoryUrl":"https://invalid.example/catalog/","engineCapabilities":["caddy.load-balancing.v1"]
    })).unwrap()).unwrap();
    let installer = Installer::open(&config).unwrap();
    let mut files = bootstrap_catalog(PIN, &keys(), now()).unwrap();
    let first = refresh(&installer, &files, now()).unwrap();
    let mut releases = Vec::new();
    let mut archives = Vec::new();
    let versions = ["1.0.0", "1.1.0", "1.2.0"];
    for version in versions {
        let mut m = manifest();
        m["version"] = version.into();
        m["target"] = target.into();
        m["resources"]["startupTimeoutMs"] = 2000.into();
        let work = root.join(version);
        fs::create_dir(&work).unwrap();
        let binary = if version == "1.2.0" {
            fs::read("/usr/bin/false").unwrap()
        } else {
            fs::read(backend).unwrap()
        };
        let (release, archive) = archive_fixture(&work, m, binary);
        releases.push(release);
        archives.push(archive);
    }
    files.extend(update(
        &first,
        json!({"formatVersion":1,"revision":2,"releases":releases,"revocations":[]}),
    ));
    let catalog = refresh(&installer, &files, now()).unwrap();
    let packages = versions
        .into_iter()
        .zip(archives)
        .map(|(v, bytes)| {
            installer
                .prepare(&catalog, ID, v, None, |_, p| fs::write(p, bytes))
                .unwrap()
        })
        .collect();
    (config, packages)
}

#[test]
fn persisted_roles_protect_against_rollback_expiry_and_partial_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let installer = manager(temp.path());
    let initial = bootstrap_catalog(PIN, &keys(), now()).unwrap();
    let first = refresh(&installer, &initial, now()).unwrap();
    let mut fresh = initial.clone();
    fresh.extend(update(&first,json!({"formatVersion":1,"revision":2,"releases":[],"revocations":[
        {"appId":ID,"version":VERSION,"revokedAt":"2026-11-01T12:00:00.000Z","reason":"withdrawn"}
    ]})));
    refresh(&installer, &fresh, now()).unwrap();
    let reopened = manager(temp.path());
    assert!(refresh(&reopened, &initial, now()).is_err());
    assert!(refresh(&reopened, &fresh, now() + Duration::days(8)).is_err());
    fresh.remove("metadata/timestamp.json");
    assert!(refresh(&reopened, &fresh, now()).is_err());
    let (_, trusted) = reopened.checkpoint().unwrap().unwrap();
    let current: Value = serde_json::from_slice(trusted.catalog_bytes()).unwrap();
    assert_eq!(current["revision"], 2);
    let checkpoint = temp.path().join("catalog-checkpoint.json");
    fs::write(checkpoint, b"{").unwrap();
    assert!(refresh(&reopened, &initial, now()).is_err());
}

#[test]
fn signed_package_stages_and_recovers_offline_with_exact_identities() {
    let store = tempfile::tempdir().unwrap();
    let fixture = tempfile::tempdir().unwrap();
    let mut installer = manager(store.path());
    let mut files = bootstrap_catalog(PIN, &keys(), now()).unwrap();
    let first = refresh(&installer, &files, now()).unwrap();
    let (mut release, archive) = package(fixture.path());
    release["packages"][0]["manifest"]["resources"]["memoryMiB"] = json!(128.0);
    files.extend(update(
        &first,
        json!({"formatVersion":1,"revision":2,"releases":[release],"revocations":[]}),
    ));
    let catalog = refresh(&installer, &files, now()).unwrap();
    installer.config.engine_capabilities.clear();
    assert!(
        installer
            .prepare(&catalog, ID, VERSION, None, |_, _| panic!(
                "incompatible package downloaded"
            ))
            .is_err()
    );
    installer
        .config
        .engine_capabilities
        .push("caddy.load-balancing.v1".into());
    let staged = installer
        .prepare(&catalog, ID, VERSION, None, |asset, path| {
            assert!(
                asset
                    .url
                    .starts_with("https://github.com/RentnerProxy/app-catalog/releases/download/")
            );
            fs::write(path, &archive)
        })
        .unwrap();
    assert_eq!(staged.archive_sha256, digest(&archive));
    assert_eq!(staged.catalog_revision, 2);
    assert_eq!(staged.manifest["resources"]["memoryMiB"], json!(128.0));
    let file = staged.directory.join("bin/app");
    assert_eq!(fs::read(&file).unwrap(), fixture_elf());
    assert!(installer.recover(ID, VERSION, "incorrect").is_err());
    let offline = manager(store.path());
    assert_eq!(
        offline
            .recover(ID, VERSION, &staged.archive_sha256)
            .unwrap()
            .directory,
        staged.directory
    );
    fs::write(&file, b"changed").unwrap();
    assert!(
        offline
            .recover(ID, VERSION, &staged.archive_sha256)
            .is_err()
    );
    fs::remove_dir_all(&staged.directory).unwrap();
    assert_eq!(
        offline
            .recover(ID, VERSION, &staged.archive_sha256)
            .unwrap()
            .directory,
        staged.directory
    );
    fs::write(
        store.path().join("archives").join(&staged.archive_sha256),
        b"changed",
    )
    .unwrap();
    assert!(
        offline
            .recover(ID, VERSION, &staged.archive_sha256)
            .is_err()
    );
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
fn verifies_dynamic_abi_against_installed_appliance_libraries() {
    let target = if cfg!(target_arch = "x86_64") {
        "linux-amd64"
    } else {
        "linux-arm64"
    };
    let mut linkage = execute(
        "inspect-elf",
        json!({"inputPath":"/usr/bin/true","target":target}),
    )
    .unwrap();
    assert!(
        linkage["needed"]
            .as_array()
            .is_some_and(|libraries| !libraries.is_empty())
    );
    linkage["path"] = Value::from("bin/app");
    super::package::verify_abi(&json!([linkage]), target).unwrap();
    linkage["versions"]["libc.so.6"] = json!(["GLIBC_TEST_UNAVAILABLE"]);
    assert!(super::package::verify_abi(&json!([linkage]), target).is_err());
}

#[test]
fn trusted_repository_setting_requires_a_plain_https_directory() {
    for value in [
        "http://example.com/",
        "https://user@example.com/",
        "https://example.com/tuf",
        "https://example.com/?key=value",
    ] {
        assert!(super::transport::repository_url(value).is_err());
    }
    assert!(super::transport::repository_url("https://example.com/tuf/").is_ok());
}
