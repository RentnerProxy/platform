use std::{
    collections::BTreeMap,
    fs, io,
    path::{Path, PathBuf},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{SigningKey, pkcs8::EncodePrivateKey};
use marketplace_app_catalog::{
    ReadOptions, SigningKeys, TrustedPackageCatalog, UpdateOptions, bootstrap_catalog,
    read_catalog, update_catalog,
};
use marketplace_app_pipeline::package::execute;
use marketplace_artifacts::digest;
use rentnerproxy_app_contracts::Contracts;
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

use super::{Config, Installer, PackageSource};

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[path = "app_install/greeting.rs"]
mod greeting;

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

fn refresh(
    manager: &Installer,
    files: &Files,
    at: OffsetDateTime,
) -> io::Result<TrustedPackageCatalog> {
    manager.refresh(
        |name, _| {
            assert!(!name.starts_with("targets/assets/"));
            Ok(files.get(name).cloned())
        },
        at,
    )
}

fn update(files: &Files, document: Value, icons: &Files) -> Files {
    let current = read_catalog(
        |name, _| Ok(files.get(name).cloned()),
        PIN,
        ReadOptions {
            now: now(),
            allow_expired_roles: false,
            next_root: None,
            previous: None,
        },
    )
    .unwrap();
    update_catalog(
        &current,
        &serde_json::to_vec(&document).unwrap(),
        &keys(),
        UpdateOptions {
            now: now(),
            next_root: None,
            icons,
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
    archive_with_documents(directory, manifest, backend, "3.1.0", [])
}

fn archive_with_documents<'a>(
    directory: &Path,
    manifest: Value,
    backend: Vec<u8>,
    openapi: &str,
    additional: impl IntoIterator<Item = (&'a str, usize, Vec<u8>)>,
) -> (Value, Vec<u8>) {
    let raw = serde_json::to_vec(&manifest).unwrap();
    let files = [
        ("app.json", 0o644, raw.clone()),
        ("bin/app", 0o755, backend),
        ("LICENSE", 0o644, b"MIT".to_vec()),
        (
            "api/openapi.json",
            0o644,
            serde_json::to_vec(
                &json!({"openapi":openapi,"info":{"title":"Probe","version":"1"},"paths":{}}),
            )
            .unwrap(),
        ),
    ];
    let archive = pack_fixture(directory, files.into_iter().chain(additional));
    let sidecar = json!({"sizeBytes":1,"sha256":"a".repeat(64)});
    let release = json!({"appId":ID,"version":manifest["version"],"source":manifest["source"],
        "publisher":{"namespace":"example","name":"Fixture"},"packages":[{"manifest":manifest,
        "archive":{"sha256":digest(&archive),"sizeBytes":archive.len()},"manifestSha256":digest(&raw),
        "sbom":sidecar,"provenance":sidecar}]});
    (release, archive)
}

fn pack_fixture<'a>(
    directory: &Path,
    files: impl IntoIterator<Item = (&'a str, usize, Vec<u8>)>,
) -> Vec<u8> {
    fs::read(pack_fixture_archive(directory, files)).unwrap()
}

fn pack_fixture_archive<'a>(
    directory: &Path,
    files: impl IntoIterator<Item = (&'a str, usize, Vec<u8>)>,
) -> PathBuf {
    let mut tar = Vec::new();
    for (path, mode, body) in files {
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
    output
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
    refresh(&installer, &files, now()).unwrap();
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
    let next = update(
        &files,
        json!({"formatVersion":1,"revision":2,"releases":releases,"revocations":[]}),
        &Files::new(),
    );
    files.extend(next);
    let catalog = refresh(&installer, &files, now()).unwrap();
    let packages = versions
        .into_iter()
        .zip(archives)
        .map(|(v, bytes)| {
            installer
                .prepare(&catalog, ID, v, PackageSource::Catalog(None), |_| {
                    Ok(io::Cursor::new(bytes))
                })
                .unwrap()
        })
        .collect();
    (config, packages)
}

#[cfg(target_os = "linux")]
pub(crate) fn revoke_lifecycle_release(config: &Path, version: &str) {
    let installer = Installer::open(config).unwrap();
    let _guard = installer.lock().unwrap();
    let (_, current) = installer.checkpoint().unwrap().unwrap();
    let mut next: Value = serde_json::from_slice(current.catalog_bytes()).unwrap();
    next["revision"] = (next["revision"].as_u64().unwrap() + 1).into();
    next["releases"]
        .as_array_mut()
        .unwrap()
        .retain(|release| release["version"] != version);
    next["revocations"].as_array_mut().unwrap().push(json!({
        "appId": ID, "version": version, "revokedAt": "2026-11-01T12:00:00.000Z", "reason": "withdrawn"
    }));
    let checkpoint: Value = serde_json::from_slice(
        &fs::read(
            installer
                .config
                .store_directory
                .join("catalog-checkpoint.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let mut files: Files = checkpoint["files"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, encoded)| {
            (
                name.clone(),
                STANDARD.decode(encoded.as_str().unwrap()).unwrap(),
            )
        })
        .collect();
    let next = update(&files, next, &Files::new());
    files.extend(next);
    refresh(&installer, &files, now()).unwrap();
}

#[test]
fn persisted_roles_protect_against_rollback_expiry_and_partial_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let installer = manager(temp.path());
    let initial = bootstrap_catalog(PIN, &keys(), now()).unwrap();
    refresh(&installer, &initial, now()).unwrap();
    let mut fresh = initial.clone();
    fresh.extend(update(&initial,json!({"formatVersion":1,"revision":2,"releases":[],"revocations":[
        {"appId":ID,"version":VERSION,"revokedAt":"2026-11-01T12:00:00.000Z","reason":"withdrawn"}
    ]}), &Files::new()));
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
    let saved: Value = serde_json::from_slice(&fs::read(&checkpoint).unwrap()).unwrap();
    for (field, value) in [
        ("acceptedAt", json!(i64::MAX)),
        ("files", json!({"metadata/1.root.json":"!"})),
        (
            "files",
            json!({"metadata/1.root.json":"A".repeat(1024 * 1024)}),
        ),
    ] {
        let mut invalid = saved.clone();
        invalid[field] = value;
        fs::write(&checkpoint, serde_json::to_vec(&invalid).unwrap()).unwrap();
        assert!(reopened.checkpoint().is_err(), "{field}");
    }
    fs::write(checkpoint, b"{").unwrap();
    assert!(refresh(&reopened, &initial, now()).is_err());
}

#[test]
fn startup_refresh_allows_local_readers_and_cannot_replace_a_newer_catalog() {
    let store = tempfile::tempdir().unwrap();
    let installer = manager(store.path());
    let initial = bootstrap_catalog(PIN, &keys(), now()).unwrap();

    installer
        .refresh_in_background(
            |name, _| {
                let _lock = installer.lock()?;
                Ok(initial.get(name).cloned())
            },
            now(),
        )
        .unwrap();

    let mut newer = initial.clone();
    newer.extend(update(
        &initial,
        json!({"formatVersion":1,"revision":2,"releases":[],"revocations":[]}),
        &Files::new(),
    ));
    let mut changed = false;
    let result = installer.refresh_in_background(
        |name, _| {
            if !changed {
                let _lock = installer.lock()?;
                refresh(&installer, &newer, now())?;
                changed = true;
            }
            Ok(initial.get(name).cloned())
        },
        now(),
    );
    assert!(result.is_err());
    assert!(changed);
    let (_, persisted) = installer.checkpoint().unwrap().unwrap();
    let document: Value = serde_json::from_slice(persisted.catalog_bytes()).unwrap();
    assert_eq!(document["revision"], 2);
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
fn bundled_installer_creates_a_protected_store_after_the_root_is_available() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let base = tempfile::tempdir_in("/run").unwrap();
    fs::set_permissions(base.path(), fs::Permissions::from_mode(0o711)).unwrap();
    let store = base.path().join("packages");
    let root = base.path().join("root.json");
    let installer = base.path().join("installer.json");
    fs::write(
        &installer,
        serde_json::to_vec(&json!({
            "storeDirectory": store,
            "pinnedRoot": root,
            "repositoryUrl": "https://invalid.example/",
            "engineCapabilities": []
        }))
        .unwrap(),
    )
    .unwrap();

    assert_eq!(
        Installer::open_bundled(&installer).err().unwrap().kind(),
        io::ErrorKind::NotFound
    );
    assert!(!store.exists());
    fs::write(&root, PIN).unwrap();
    let configured = Installer::open_bundled(&installer).unwrap();
    assert_eq!(configured.pinned_root, PIN);
    let metadata = fs::metadata(&store).unwrap();
    assert_eq!(metadata.uid(), 0);
    assert_eq!(metadata.mode() & 0o777, 0o711);
    assert_eq!(
        Installer::open_bundled(&installer)
            .unwrap()
            .config
            .store_directory,
        store
    );
}

#[test]
fn signed_package_preparation_enforces_ui_limits_for_fresh_and_cached_trees() {
    let limit = super::package::UI_ASSET_LIMIT as usize;
    for (ui, openapi, asset_size, expected_error) in [
        (false, "3.0.3", 0, None),
        (true, "3.1.0", limit, None),
        (true, "3.0.3", 1, Some("UI packages require OpenAPI 3.1")),
        (
            true,
            "3.1.0",
            limit + 1,
            Some("UI assets must be regular files no larger than 8 MiB"),
        ),
    ] {
        let store = tempfile::tempdir().unwrap();
        let fixture = tempfile::tempdir().unwrap();
        let installer = manager(store.path());
        let mut files = bootstrap_catalog(PIN, &keys(), now()).unwrap();
        refresh(&installer, &files, now()).unwrap();
        let mut manifest = manifest();
        let mut assets = Vec::new();
        if ui {
            manifest["ui"] = json!({"entrypoint":"ui/index.html", "slots":["navigation"]});
            manifest["requires"]["uiBridge"] = json!(">=1.0.0 <2.0.0");
            assets.push(("ui/index.html", 0o644, b"<h1>Fixture</h1>".to_vec()));
            assets.push(("ui/static/image.png", 0o644, vec![0; asset_size]));
        }
        let (release, archive) = archive_with_documents(
            fixture.path(),
            manifest.clone(),
            fixture_elf(),
            openapi,
            assets,
        );
        let package = &release["packages"][0];
        let archive_hash = package["archive"]["sha256"].as_str().unwrap();
        files.extend(update(
            &files,
            json!({"formatVersion":1,"revision":2,"releases":[release],"revocations":[]}),
            &Files::new(),
        ));
        let catalog = refresh(&installer, &files, now()).unwrap();
        let fresh = installer.prepare(&catalog, ID, VERSION, PackageSource::Catalog(None), |_| {
            Ok(archive.as_slice())
        });
        let Some(expected) = expected_error else {
            let staged = fresh.unwrap();
            assert_eq!(
                installer
                    .recover(ID, VERSION, archive_hash)
                    .unwrap()
                    .directory,
                staged.directory
            );
            continue;
        };
        let error = fresh.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), expected);
        let packages = store.path().join("packages");
        let destination = packages.join(archive_hash);
        assert!(!destination.exists());

        // Recreate a receipt and tree produced under the previous admission rules.
        let checked = execute(
            "validate-package",
            json!({
                "archivePath": fixture.path().join("fixture.tar"), "outputDirectory": destination,
                "target": TARGET, "source": manifest["source"],
            }),
        )
        .unwrap();
        super::filesystem::sync_tree(&destination).unwrap();
        let receipt = tempfile::NamedTempFile::new_in(&packages).unwrap();
        serde_json::to_writer(receipt.as_file(), &json!({
            "archive": package["archive"], "manifestSha256": package["manifestSha256"],
            "target": TARGET, "treeSha256": super::filesystem::tree_digest(&destination).unwrap(),
            "linkage": checked["linkage"],
        })).unwrap();
        receipt
            .persist(packages.join(format!(".verified-v1-{archive_hash}.json")))
            .unwrap();
        let error = installer.recover(ID, VERSION, archive_hash).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), expected);
    }
}

#[test]
fn signed_package_stages_and_recovers_offline_with_exact_identities() {
    let store = tempfile::tempdir().unwrap();
    let fixture = tempfile::tempdir().unwrap();
    let mut installer = manager(store.path());
    let mut files = bootstrap_catalog(PIN, &keys(), now()).unwrap();
    refresh(&installer, &files, now()).unwrap();
    let (mut release, archive) = package(fixture.path());
    release["packages"][0]["manifest"]["resources"]["memoryMiB"] = json!(128.0);
    let icon = b"signed fixture icon";
    let icon_hash = digest(icon);
    release["icon"] = json!({"format":"png","sha256":icon_hash,"sizeBytes":icon.len()});
    let next = update(
        &files,
        json!({"formatVersion":1,"revision":2,"releases":[release],"revocations":[]}),
        &Files::from([(format!("assets/{icon_hash}.png"), icon.to_vec())]),
    );
    files.extend(next);
    let catalog = refresh(&installer, &files, now()).unwrap();
    let archive_hash = digest(&archive);
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        let entries = serde_json::to_value(installer.catalog_entries(&catalog).unwrap()).unwrap();
        assert_eq!(entries.as_array().unwrap().len(), 1);
        assert_eq!(entries[0]["appId"], ID);
        assert_eq!(entries[0]["version"], VERSION);
        assert_eq!(entries[0]["archiveSha256"], archive_hash);
        assert_eq!(entries[0]["name"], "Probe");
        assert_eq!(entries[0]["availability"], "available");
    }
    let error = installer
        .prepare::<io::Empty>(
            &catalog,
            ID,
            VERSION,
            PackageSource::Catalog(Some(&"f".repeat(64))),
            |_| panic!("a different signed archive reached the download boundary"),
        )
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "Package identity differs from the signed catalog"
    );
    let checkpoint: Value =
        serde_json::from_slice(&fs::read(store.path().join("catalog-checkpoint.json")).unwrap())
            .unwrap();
    assert!(
        checkpoint["files"]
            .as_object()
            .unwrap()
            .keys()
            .all(|path| !path.starts_with("targets/assets/"))
    );
    installer.config.engine_capabilities.clear();
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        let entries = serde_json::to_value(installer.catalog_entries(&catalog).unwrap()).unwrap();
        assert_eq!(entries[0]["availability"], "incompatible");
    }
    assert!(
        installer
            .prepare::<io::Empty>(
                &catalog,
                ID,
                VERSION,
                PackageSource::Catalog(None),
                |_| panic!("incompatible package downloaded")
            )
            .is_err()
    );
    installer
        .config
        .engine_capabilities
        .push("caddy.load-balancing.v1".into());
    let archives = store.path().join("archives");
    let packages = store.path().join("packages");
    assert!(
        installer
            .prepare(&catalog, ID, VERSION, PackageSource::Catalog(None), |_| Ok(
                &b"partial"[..]
            ))
            .is_err()
    );
    assert!(!archives.join(&archive_hash).exists());
    assert_eq!(fs::read_dir(&archives).unwrap().count(), 0);
    let partial = super::filesystem::private_workspace(&archives, ".download-")
        .unwrap()
        .keep();
    fs::write(partial.join("archive"), b"interrupted transfer").unwrap();
    let staged =
        installer
            .prepare(
                &catalog,
                ID,
                VERSION,
                PackageSource::Catalog(Some(&archive_hash)),
                |asset| {
                    assert!(asset.url.starts_with(
                        "https://github.com/RentnerProxy/app-catalog/releases/download/"
                    ));
                    Ok(archive.as_slice())
                },
            )
            .unwrap();
    assert!(!partial.exists());
    assert_eq!(staged.archive_sha256, archive_hash);
    assert_eq!(staged.catalog_revision, 2);
    assert_eq!(staged.manifest["resources"]["memoryMiB"], json!(128.0));
    let file = staged.directory.join("bin/app");
    assert_eq!(fs::read(&file).unwrap(), fixture_elf());
    assert!(installer.recover(ID, VERSION, "incorrect").is_err());
    let offline = manager(store.path());
    let receipt = packages.join(format!(".verified-v1-{archive_hash}.json"));
    assert!(receipt.is_file());
    #[cfg(unix)]
    let package_mtime = {
        let previous = std::time::UNIX_EPOCH + std::time::Duration::from_secs(123);
        fs::File::open(&packages)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(previous))
            .unwrap();
        previous
    };
    assert_eq!(
        offline
            .recover(ID, VERSION, &staged.archive_sha256)
            .unwrap()
            .directory,
        staged.directory
    );
    #[cfg(unix)]
    assert_eq!(
        fs::metadata(&packages).unwrap().modified().unwrap(),
        package_mtime
    );
    fs::remove_file(&receipt).unwrap();
    offline
        .recover(ID, VERSION, &staged.archive_sha256)
        .unwrap();
    assert!(receipt.is_file());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&receipt, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            offline
                .recover(ID, VERSION, &staged.archive_sha256)
                .unwrap_err()
                .to_string(),
            "Invalid package verification receipt"
        );
        fs::set_permissions(&receipt, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let unexpected = staged.directory.join("bin/unrecorded");
    fs::write(&unexpected, b"not in the signed archive").unwrap();
    assert!(
        offline
            .recover(ID, VERSION, &staged.archive_sha256)
            .is_err()
    );
    fs::remove_file(unexpected).unwrap();
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
    let cached_archive = store.path().join("archives").join(&staged.archive_sha256);
    fs::write(&cached_archive, b"changed").unwrap();
    assert!(
        offline
            .recover(ID, VERSION, &staged.archive_sha256)
            .is_err()
    );
    assert!(
        installer
            .prepare(&catalog, ID, VERSION, PackageSource::Catalog(None), |_| Ok(
                &b"invalid retry"[..]
            ))
            .is_err()
    );
    assert_eq!(fs::read(&cached_archive).unwrap(), b"changed");
    assert_eq!(
        installer
            .prepare(&catalog, ID, VERSION, PackageSource::Catalog(None), |_| Ok(
                archive.as_slice()
            ))
            .unwrap()
            .directory,
        staged.directory
    );
    assert_eq!(fs::read(&cached_archive).unwrap(), archive);
    fs::remove_file(&cached_archive).unwrap();
    assert!(
        offline
            .recover(ID, VERSION, &staged.archive_sha256)
            .is_err()
    );
    fs::write(&cached_archive, &archive).unwrap();
    let abandoned = super::filesystem::private_workspace(&packages, ".stage-interrupted")
        .unwrap()
        .keep();
    fs::write(abandoned.join("package.tar"), b"interrupted").unwrap();
    offline
        .recover(ID, VERSION, &staged.archive_sha256)
        .unwrap();
    assert!(!abandoned.exists());
    #[cfg(unix)]
    {
        let unexpected = store.path().join("packages/.stage-unexpected");
        std::os::unix::fs::symlink(fixture.path(), &unexpected).unwrap();
        assert_eq!(
            offline
                .recover(ID, VERSION, &staged.archive_sha256)
                .unwrap_err()
                .to_string(),
            "Invalid abandoned package workspace"
        );
        assert!(fixture.path().is_dir());
        fs::remove_file(unexpected).unwrap();
    }

    let next = update(
        &files,
        json!({
            "formatVersion":1,"revision":3,"releases":[],"revocations":[
                {"appId":ID,"version":VERSION,"revokedAt":"2026-11-01T12:00:00.000Z","reason":"withdrawn"}
            ]
        }),
        &Files::new(),
    );
    files.extend(next);
    refresh(&installer, &files, now()).unwrap();
    assert!(
        offline
            .recover(ID, VERSION, &staged.archive_sha256)
            .is_err()
    );
    assert_eq!(fs::read(file).unwrap(), fixture_elf());
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
    let directory = tempfile::tempdir().unwrap();
    let executable = directory.path().join("app");
    // The package verifier requires a regular file with a single link.
    fs::copy("/usr/bin/true", &executable).unwrap();
    let mut linkage = execute(
        "inspect-elf",
        json!({"inputPath":executable,"target":target}),
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
    assert!(super::package::verify_abi(&json!([]), "linux-unsupported").is_err());
    assert_eq!(
        super::package::verify_abi(
            &json!([{"path": "bin/app", "needed": ["libfixture-unavailable.so"], "interpreter": null, "versions": {}}]),
            target,
        )
        .unwrap_err()
        .kind(),
        io::ErrorKind::NotFound
    );
    assert_eq!(
        super::package::verify_abi(
            &json!([{"path": "bin/app", "needed": [], "interpreter": "/", "versions": {}}]),
            target,
        )
        .unwrap_err()
        .to_string(),
        "Invalid ELF interpreter"
    );
    for invalid_name in ["/lib/libc.so.6", "../libc.so.6", "lib\\libc.so.6", ".."] {
        assert_eq!(
            super::package::verify_abi(
                &json!([{"needed": [invalid_name], "interpreter": null}]),
                target,
            )
            .unwrap_err()
            .to_string(),
            "ELF dependency must name an appliance library"
        );
    }
}

#[cfg(unix)]
#[test]
fn staging_tree_refuses_special_files_before_touching_their_targets() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let directory = tempfile::tempdir().unwrap();
    let stage = directory.path().join("stage");
    let outside = directory.path().join("outside");
    fs::create_dir(&stage).unwrap();
    fs::write(&outside, b"preserved").unwrap();
    fs::set_permissions(&outside, fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&outside, stage.join("entry")).unwrap();
    assert!(super::filesystem::sync_tree(&stage).is_err());
    assert_eq!(
        fs::metadata(&outside).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let lock = directory.path().join(".install.lock");
    symlink(&outside, &lock).unwrap();
    assert!(super::filesystem::lock(directory.path()).is_err());
    assert_eq!(fs::read(outside).unwrap(), b"preserved");

    assert!(super::filesystem::directory(&lock, 0o711).is_err());
    fs::set_permissions(&stage, fs::Permissions::from_mode(0o770)).unwrap();
    assert!(super::filesystem::directory(&stage, 0o711).is_err());
    fs::set_permissions(&stage, fs::Permissions::from_mode(0o700)).unwrap();
    super::filesystem::directory(&stage, 0o711).unwrap();
    assert_eq!(
        fs::metadata(&stage).unwrap().permissions().mode() & 0o777,
        0o711
    );
    assert!(super::filesystem::directory(&directory.path().join("absent/child"), 0o711).is_err());
}

#[test]
fn installer_lock_reports_a_busy_store_after_a_bounded_wait() {
    let directory = tempfile::tempdir().unwrap();
    let lock = super::filesystem::lock(directory.path()).unwrap();
    let error = super::filesystem::lock(directory.path()).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    drop(lock);
    assert!(super::filesystem::lock(directory.path()).is_ok());
}

#[test]
fn trusted_repository_setting_requires_a_plain_https_directory() {
    for value in [
        "invalid catalog path",
        "http://example.com/",
        "https://user@example.com/",
        "https://:password@example.com/",
        "https://example.com/tuf",
        "https://example.com/?key=value",
        "https://example.com/tuf/#fragment",
    ] {
        assert!(super::transport::repository_url(value).is_err());
    }
    assert!(super::transport::repository_url("https://example.com/tuf/").is_ok());
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
fn installer_respects_root_path_admission_and_retains_its_catalog_when_refresh_fails() {
    use std::{
        os::unix::fs::{PermissionsExt, symlink},
        process::ExitCode,
    };

    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let temporary = tempfile::tempdir_in("/root").unwrap();
    let root = temporary.path();
    let package_directory = tempfile::tempdir_in("/run").unwrap();
    let store = package_directory.path().join("store");
    let pin = root.join("root.json");
    let config = root.join("installer.json");
    fs::create_dir(&store).unwrap();
    fs::set_permissions(package_directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&store, fs::Permissions::from_mode(0o711)).unwrap();
    fs::create_dir(root.join("private")).unwrap();
    fs::write(&pin, PIN).unwrap();
    let settings = json!({
        "storeDirectory":store,"pinnedRoot":pin,
        "repositoryUrl":"https://127.0.0.1:0/","engineCapabilities":[]
    });
    let write_settings =
        |value: &Value| fs::write(&config, serde_json::to_vec(value).unwrap()).unwrap();
    write_settings(&settings);
    assert_eq!(
        Installer::open(&config).err().unwrap().to_string(),
        "Application package store paths must be searchable by app identities"
    );
    fs::set_permissions(package_directory.path(), fs::Permissions::from_mode(0o711)).unwrap();
    let installer = Installer::open(&config).unwrap();
    {
        let _writer = installer.lock().unwrap();
        assert_eq!(
            installer.stage(ID, VERSION).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(
            installer
                .recover(ID, VERSION, &"0".repeat(64))
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
    }
    assert!(installer.recover(ID, VERSION, &"0".repeat(64)).is_err());
    let files = bootstrap_catalog(PIN, &keys(), now()).unwrap();
    refresh(&installer, &files, now()).unwrap();
    let checkpoint = store.join("catalog-checkpoint.json");
    let accepted = fs::read(&checkpoint).unwrap();
    assert!(refresh(&installer, &files, now() - Duration::seconds(1)).is_err());
    let command = [
        config.to_str().unwrap().to_owned(),
        ID.into(),
        VERSION.into(),
    ];
    assert_eq!(
        super::run_app_stage(command.clone().into_iter()),
        ExitCode::FAILURE
    );
    assert_eq!(
        super::run_app_stage(command.into_iter().take(2)),
        ExitCode::FAILURE
    );
    assert_eq!(fs::read(&checkpoint).unwrap(), accepted);
    assert!(super::filesystem::check_root_path(Path::new("catalog.json"), false).is_err());
    assert!(super::filesystem::check_root_path(&pin, true).is_err());
    assert!(
        super::filesystem::check_root_path(&root.join("private/../installer.json"), false).is_err()
    );

    let alias = root.join("alias.json");
    symlink(&config, &alias).unwrap();
    assert!(Installer::open(&alias).is_err());
    fs::set_permissions(&config, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(Installer::open(&config).is_err());
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
    for (field, value) in [
        ("pinnedRoot", json!(store)),
        ("storeDirectory", json!(pin)),
        ("engineCapabilities", json!(["unknown-engine"])),
        ("repositoryUrl", json!("http://example.com/")),
        ("unknownField", Value::Bool(true)),
    ] {
        let mut changed = settings.clone();
        changed[field] = value;
        write_settings(&changed);
        assert!(Installer::open(&config).is_err(), "{field}");
    }
    assert_eq!(fs::read(&checkpoint).unwrap(), accepted);

    let mut inconsistent: Value = serde_json::from_slice(&accepted).unwrap();
    inconsistent["pinSha256"] = "0".repeat(64).into();
    fs::write(&checkpoint, serde_json::to_vec(&inconsistent).unwrap()).unwrap();
    assert!(installer.checkpoint().is_err());
}
