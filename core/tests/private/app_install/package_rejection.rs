//! Signed packages that do not match their release, collide with published identities or carry
//! unsafe archive entries are refused before anything is published to the package store.

use std::{ffi::OsString, fs, io, path::Path};

use ed25519_dalek::{Signer, SigningKey};
use marketplace_app_catalog::{TrustedPackageCatalog, bootstrap_catalog};
use marketplace_app_pipeline::package::execute;
use marketplace_artifacts::digest;
use serde_json::{Value, json};

use super::{
    Files, ID, Installer, PIN, PackageSource, VERSION, fixture_elf, keys, manager, manifest, now,
    refresh, update,
};

const CHECKPOINT: &str = "catalog-checkpoint.json";
const OTHER_TARGET: &str = "linux-arm64";
/// One more than the per-file limit of the package validator.
const OVERSIZED_FILE: u64 = 64 * 1024 * 1024 + 1;
/// One more than the entry limit of the package validator.
const TOO_MANY_ENTRIES: usize = 4097;
/// Online role signing seeds of `keys()`.
const ROLE_SEEDS: [(&str, u8); 3] = [("targets", 3), ("snapshot", 4), ("timestamp", 5)];

struct Entry {
    path: String,
    mode: u32,
    kind: u8,
    link: String,
    device: Option<(u32, u32)>,
    body: Vec<u8>,
    zeros: u64,
}

impl Entry {
    fn file(path: &str, mode: u32, body: impl Into<Vec<u8>>) -> Self {
        Self {
            path: path.into(),
            mode,
            kind: b'0',
            link: String::new(),
            device: None,
            body: body.into(),
            zeros: 0,
        }
    }

    fn special(path: &str, kind: u8, link: &str) -> Self {
        Self {
            kind,
            link: link.into(),
            ..Self::file(path, 0o644, Vec::new())
        }
    }

    fn zeros(path: &str, size: u64) -> Self {
        Self {
            zeros: size,
            ..Self::file(path, 0o644, Vec::new())
        }
    }
}

/// The entries of a valid fixture package for `manifest`.
fn entries(manifest: &Value) -> Vec<Entry> {
    let api = json!({"openapi":"3.1.0","info":{"title":"Probe","version":"1"},"paths":{}});
    vec![
        Entry::file("app.json", 0o644, serde_json::to_vec(manifest).unwrap()),
        Entry::file("bin/app", 0o755, fixture_elf()),
        Entry::file("LICENSE", 0o644, *b"MIT"),
        Entry::file("api/openapi.json", 0o644, serde_json::to_vec(&api).unwrap()),
    ]
}

/// Write raw ustar headers, so that each entry can carry unsafe metadata.
fn ustar(entries: &[Entry]) -> Vec<u8> {
    fn octal(field: &mut [u8], value: u64) {
        let width = field.len() - 1;
        field[..width].copy_from_slice(format!("{value:0width$o}").as_bytes());
    }
    let mut tar = Vec::new();
    for entry in entries {
        let size = entry.body.len() as u64 + entry.zeros;
        let mut header = [0; 512];
        header[..entry.path.len()].copy_from_slice(entry.path.as_bytes());
        octal(&mut header[100..108], entry.mode.into());
        octal(&mut header[108..116], 0);
        octal(&mut header[116..124], 0);
        octal(&mut header[124..136], size);
        octal(&mut header[136..148], 0);
        header[156] = entry.kind;
        header[157..157 + entry.link.len()].copy_from_slice(entry.link.as_bytes());
        header[257..265].copy_from_slice(b"ustar\x0000");
        if let Some((major, minor)) = entry.device {
            octal(&mut header[329..337], major.into());
            octal(&mut header[337..345], minor.into());
        }
        header[148..156].fill(b' ');
        let checksum = header.iter().map(|&byte| u64::from(byte)).sum();
        octal(&mut header[148..155], checksum);
        tar.extend_from_slice(&header);
        tar.extend_from_slice(&entry.body);
        tar.resize(tar.len() + entry.zeros as usize, 0);
        tar.resize(tar.len().next_multiple_of(512), 0);
    }
    tar.resize(tar.len() + 1024, 0);
    tar
}

/// Compress like the Marketplace publisher. The uncompressed input is removed at once.
fn compress(directory: &Path, entries: &[Entry]) -> Vec<u8> {
    let input = directory.join("candidate.tar");
    let output = directory.join("candidate.tar.zst");
    fs::write(&input, ustar(entries)).unwrap();
    let compressed = execute(
        "compress-package",
        json!({"inputPath": input, "outputPath": output}),
    );
    fs::remove_file(&input).unwrap();
    compressed.unwrap();
    let archive = fs::read(&output).unwrap();
    fs::remove_file(output).unwrap();
    archive
}

/// A release by the fixture publisher, whose namespace is `example`.
fn release(app_id: &str, packages: &[(&Value, &[u8])]) -> Value {
    let sidecar = json!({"sizeBytes":1,"sha256":"a".repeat(64)});
    let packages: Vec<_> = packages
        .iter()
        .map(|(manifest, archive)| {
            json!({
                "manifest": manifest,
                "archive": {"sha256": digest(archive), "sizeBytes": archive.len()},
                "manifestSha256": digest(&serde_json::to_vec(manifest).unwrap()),
                "sbom": sidecar, "provenance": sidecar,
            })
        })
        .collect();
    let first = packages[0]["manifest"].clone();
    json!({
        "appId": app_id, "version": first["version"], "source": first["source"],
        "publisher": {"namespace": "example", "name": "Fixture"}, "packages": packages,
    })
}

fn signed(manifest: &Value, archive: &[u8]) -> Value {
    release(ID, &[(manifest, archive)])
}

fn versioned(version: &str) -> Value {
    let mut manifest = manifest();
    manifest["version"] = version.into();
    manifest
}

fn document(revision: u64, releases: Vec<Value>, revocations: Vec<Value>) -> Value {
    json!({
        "formatVersion": 1, "revision": revision,
        "releases": releases, "revocations": revocations,
    })
}

struct Fixture {
    store: tempfile::TempDir,
    work: tempfile::TempDir,
    installer: Installer,
    files: Files,
    revision: u64,
}

impl Fixture {
    fn new() -> Self {
        Self::with_store(tempfile::tempdir().unwrap())
    }

    fn with_store(store: tempfile::TempDir) -> Self {
        let installer = manager(store.path());
        let files = bootstrap_catalog(PIN, &keys(), now()).unwrap();
        refresh(&installer, &files, now()).unwrap();
        Self {
            store,
            work: tempfile::tempdir().unwrap(),
            installer,
            files,
            revision: 1,
        }
    }

    fn package(&self, manifest: &Value) -> Vec<u8> {
        compress(self.work.path(), &entries(manifest))
    }

    fn publish(&mut self, releases: Vec<Value>) -> TrustedPackageCatalog {
        self.revision += 1;
        let next = update(
            &self.files,
            document(self.revision, releases, vec![]),
            &Files::new(),
        );
        self.files.extend(next);
        refresh(&self.installer, &self.files, now()).unwrap()
    }

    fn checkpoint(&self) -> Vec<u8> {
        fs::read(self.store.path().join(CHECKPOINT)).unwrap()
    }

    /// Sorted names in a store directory, including workspaces and receipts.
    fn listing(&self, directory: &str) -> Vec<OsString> {
        let Ok(entries) = fs::read_dir(self.store.path().join(directory)) else {
            return Vec::new();
        };
        let mut names: Vec<_> = entries.map(|entry| entry.unwrap().file_name()).collect();
        names.sort();
        names
    }

    fn workspaces(&self) -> Vec<OsString> {
        ["archives", "packages"]
            .into_iter()
            .flat_map(|directory| self.listing(directory))
            .filter(|name| {
                let name = name.to_string_lossy();
                [".download-", ".stage-", ".candidate-package-"]
                    .iter()
                    .any(|prefix| name.starts_with(prefix))
            })
            .collect()
    }

    /// Stage authentic signed bytes that the package validator must refuse.
    fn refuse(&self, catalog: &TrustedPackageCatalog, version: &str, archive: &[u8]) -> io::Error {
        let packages = self.listing("packages");
        let error = self
            .installer
            .prepare(catalog, ID, version, PackageSource::Catalog(None), |_| {
                Ok(archive)
            })
            .unwrap_err();
        let sha256 = digest(archive);
        assert!(!self.store.path().join("packages").join(&sha256).exists());
        assert_eq!(self.listing("packages"), packages, "{version}: {error}");
        assert_eq!(self.workspaces(), Vec::<OsString>::new(), "{version}");
        error
    }
}

/// Re-sign the online roles of an update around other catalog bytes. With `flip`, one hex
/// digit of that role's signature changes after signing; its parents still link the result.
fn relink(next: &Files, catalog: &[u8], flip: Option<&str>) -> Files {
    fn canonical(value: &Value) -> Vec<u8> {
        let mut bytes = Vec::new();
        match value {
            Value::Object(map) => {
                let mut keys: Vec<_> = map.keys().collect();
                keys.sort();
                bytes.push(b'{');
                for (index, key) in keys.into_iter().enumerate() {
                    if index > 0 {
                        bytes.push(b',');
                    }
                    bytes.extend(serde_json::to_vec(key).unwrap());
                    bytes.push(b':');
                    bytes.extend(canonical(&map[key]));
                }
                bytes.push(b'}');
            }
            Value::Array(items) => {
                bytes.push(b'[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        bytes.push(b',');
                    }
                    bytes.extend(canonical(item));
                }
                bytes.push(b']');
            }
            scalar => bytes.extend(serde_json::to_vec(scalar).unwrap()),
        }
        bytes
    }
    let file = |bytes: &[u8]| json!({"length": bytes.len(), "hashes": {"sha256": digest(bytes)}});
    let mut files = next.clone();
    files.retain(|path, _| !path.ends_with(".catalog.json"));
    files.insert(
        format!("targets/{}.catalog.json", digest(catalog)),
        catalog.to_vec(),
    );
    let mut linked = file(catalog);
    for (role, seed) in ROLE_SEEDS {
        let path = if role == "timestamp" {
            "metadata/timestamp.json".to_owned()
        } else {
            files
                .keys()
                .find(|path| path.ends_with(&format!(".{role}.json")))
                .unwrap_or_else(|| panic!("the update signs a new {role} role"))
                .clone()
        };
        let mut envelope: Value = serde_json::from_slice(&files[&path]).unwrap();
        let signed = &mut envelope["signed"];
        match role {
            "targets" => signed["targets"]["catalog.json"] = linked,
            _ => {
                let child = if role == "snapshot" {
                    "targets.json"
                } else {
                    "snapshot.json"
                };
                linked["version"] = signed["meta"][child]["version"].clone();
                signed["meta"][child] = linked;
            }
        }
        let signature = SigningKey::from_bytes(&[seed; 32]).sign(&canonical(signed));
        let mut sig: String = signature
            .to_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        if flip == Some(role) {
            let digit = if sig.starts_with('0') { "1" } else { "0" };
            sig.replace_range(..1, digit);
        }
        envelope["signatures"][0]["sig"] = sig.into();
        let bytes = serde_json::to_vec(&envelope).unwrap();
        linked = file(&bytes);
        files.insert(path, bytes);
    }
    files
}

/// The catalog bytes that an update signed.
fn catalog_bytes(next: &Files) -> Vec<u8> {
    next.iter()
        .find(|(path, _)| path.ends_with(".catalog.json"))
        .map(|(_, bytes)| bytes.clone())
        .unwrap()
}

#[test]
fn release_without_this_target_never_reaches_the_download_boundary() {
    let mut fixture = Fixture::new();
    let mut other = manifest();
    other["target"] = OTHER_TARGET.into();
    let archive = fixture.package(&other);
    let catalog = fixture.publish(vec![signed(&other, &archive)]);
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        let entries = fixture.installer.catalog_entries(&catalog).unwrap();
        assert!(entries.is_empty());
    }
    let error = fixture
        .installer
        .prepare::<io::Empty>(&catalog, ID, VERSION, PackageSource::Catalog(None), |_| {
            panic!("a release for {OTHER_TARGET} reached the download boundary")
        })
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "App release is revoked, missing, or unavailable for this target"
    );
    assert_eq!(fixture.listing("archives"), Vec::<OsString>::new());
    assert_eq!(fixture.listing("packages"), Vec::<OsString>::new());
}

#[test]
fn packaged_manifest_must_match_the_signed_release() {
    let mut fixture = Fixture::new();
    let accepted = versioned(VERSION);
    let accepted_archive = fixture.package(&accepted);
    let mut releases = vec![signed(&accepted, &accepted_archive)];
    let mut cases = Vec::new();
    for (index, (field, value, expected)) in [
        (
            "/id",
            json!("other.probe"),
            "Packaged manifest differs from the signed catalog",
        ),
        (
            "/version",
            json!("9.0.0"),
            "Packaged manifest differs from the signed catalog",
        ),
        (
            "/target",
            json!(OTHER_TARGET),
            "Candidate runtime does not satisfy the manifest requirements",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let version = format!("1.0.{}", index + 1);
        let signed_manifest = versioned(&version);
        let mut packaged = signed_manifest.clone();
        *packaged.pointer_mut(field).unwrap() = value;
        let archive = fixture.package(&packaged);
        releases.push(signed(&signed_manifest, &archive));
        cases.push((field, version, archive, expected));
    }
    let catalog = fixture.publish(releases);
    fixture
        .installer
        .prepare(&catalog, ID, VERSION, PackageSource::Catalog(None), |_| {
            Ok(accepted_archive.as_slice())
        })
        .unwrap();
    for (field, version, archive, expected) in cases {
        let error = fixture.refuse(&catalog, &version, &archive);
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{field}");
        assert_eq!(error.to_string(), expected, "{field}");
    }
}

#[test]
fn unsafe_archive_entries_are_refused_before_publication() {
    let mut fixture = Fixture::new();
    let outside = tempfile::tempdir().unwrap();
    let sentinel = outside.path().join("sentinel");
    fs::write(&sentinel, b"preserved").unwrap();
    let sentinel_path = sentinel.to_str().unwrap().to_owned();
    let unsupported = "Only regular ustar files and directories are supported";
    let metadata = "Invalid ustar permissions, file size or device metadata";
    let duplicate = "Conflicting or duplicate ustar package path";
    type Change = Box<dyn Fn(&mut Vec<Entry>)>;
    let cases: Vec<(&str, &str, Change)> = vec![
        (
            "parent traversal",
            "Unsafe ustar package path",
            Box::new(|entries| entries.push(Entry::file("../x", 0o644, *b"escaped"))),
        ),
        (
            "absolute path",
            "Unsafe ustar package path",
            Box::new(|entries| entries.push(Entry::file("/bin/app", 0o755, fixture_elf()))),
        ),
        (
            "hard link",
            unsupported,
            Box::new(|entries| entries.push(Entry::special("licenses/hard", b'1', "bin/app"))),
        ),
        (
            "symbolic link",
            unsupported,
            Box::new(move |entries| {
                entries.push(Entry::special("licenses/soft", b'2', &sentinel_path));
            }),
        ),
        (
            "character device",
            unsupported,
            Box::new(|entries| {
                entries.push(Entry {
                    device: Some((1, 3)),
                    ..Entry::special("licenses/null", b'3', "")
                });
            }),
        ),
        (
            "FIFO",
            unsupported,
            Box::new(|entries| entries.push(Entry::special("licenses/fifo", b'6', ""))),
        ),
        (
            "setuid executable",
            metadata,
            Box::new(|entries| entries[1].mode = 0o4755),
        ),
        (
            "group-writable document",
            metadata,
            Box::new(|entries| entries[3].mode = 0o664),
        ),
        (
            "duplicate path",
            duplicate,
            Box::new(|entries| entries.push(Entry::file("bin/app", 0o755, fixture_elf()))),
        ),
        (
            "case-variant duplicate path",
            duplicate,
            Box::new(|entries| entries.push(Entry::file("api/OpenAPI.json", 0o644, *b"{}"))),
        ),
        (
            "entry count",
            "Candidate archive has too many entries",
            Box::new(|entries| {
                for index in entries.len()..TOO_MANY_ENTRIES {
                    entries.push(Entry::file(
                        &format!("licenses/n{index:04}"),
                        0o644,
                        Vec::new(),
                    ));
                }
            }),
        ),
        (
            "expanded file size",
            metadata,
            Box::new(|entries| entries.push(Entry::zeros("licenses/large", OVERSIZED_FILE))),
        ),
    ];

    let accepted = versioned(VERSION);
    let accepted_archive = fixture.package(&accepted);
    let mut releases = vec![signed(&accepted, &accepted_archive)];
    let mut archives = Vec::new();
    for (index, (name, _, change)) in cases.iter().enumerate() {
        let version = format!("1.0.{}", index + 1);
        let manifest = versioned(&version);
        let mut candidate = entries(&manifest);
        change(&mut candidate);
        let archive = compress(fixture.work.path(), &candidate);
        if *name == "expanded file size" {
            // The signed transfer stays small; only extraction would expand it.
            assert!(archive.len() < 1024 * 1024);
        }
        releases.push(signed(&manifest, &archive));
        archives.push((version, archive));
    }
    let catalog = fixture.publish(releases);
    fixture
        .installer
        .prepare(&catalog, ID, VERSION, PackageSource::Catalog(None), |_| {
            Ok(accepted_archive.as_slice())
        })
        .unwrap();

    for ((name, expected, _), (version, archive)) in cases.iter().zip(&archives) {
        let error = fixture.refuse(&catalog, version, archive);
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{name}: {error}");
        assert_eq!(error.to_string(), *expected, "{name}");
        assert_eq!(fs::read(&sentinel).unwrap(), b"preserved", "{name}");
        let outside_entries: Vec<_> = fs::read_dir(outside.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(outside_entries, ["sentinel"], "{name}");
    }
}

#[test]
fn catalogs_with_colliding_identities_are_not_accepted() {
    let fixture = Fixture::new();
    let accepted = versioned(VERSION);
    let archive = fixture.package(&accepted);
    let mut changed = accepted.clone();
    changed["display"]["summary"] = "Same identity, other bytes".into();
    let other_archive = fixture.package(&changed);
    let original = signed(&accepted, &archive);
    let next = update(
        &fixture.files,
        document(2, vec![original.clone()], vec![]),
        &Files::new(),
    );
    let revocation = json!({
        "appId": ID, "version": VERSION, "revokedAt": "2026-11-01T12:00:00.000Z",
        "reason": "withdrawn",
    });
    let mut other_namespace = accepted.clone();
    other_namespace["id"] = "other.probe".into();
    let checkpoint = fixture.checkpoint();
    for (name, colliding, expected) in [
        (
            "release and revocation of one version",
            document(2, vec![original.clone()], vec![revocation]),
            "Invalid catalog: invalidCatalog",
        ),
        (
            "two releases of one version",
            document(
                2,
                vec![original.clone(), signed(&accepted, &other_archive)],
                vec![],
            ),
            "Invalid catalog: invalidCatalog",
        ),
        (
            "two packages for one target",
            document(
                2,
                vec![release(
                    ID,
                    &[(&accepted, &archive), (&accepted, &other_archive)],
                )],
                vec![],
            ),
            "Invalid catalog: invalidRelease",
        ),
        (
            "app outside the publisher namespace",
            document(
                2,
                vec![release("other.probe", &[(&other_namespace, &archive)])],
                vec![],
            ),
            "Invalid catalog: invalidRelease",
        ),
    ] {
        let mut served = fixture.files.clone();
        served.extend(relink(
            &next,
            &serde_json::to_vec(&colliding).unwrap(),
            None,
        ));
        let error = refresh(&fixture.installer, &served, now()).err().unwrap();
        assert_eq!(error.to_string(), expected, "{name}");
        assert_eq!(fixture.checkpoint(), checkpoint, "{name}");
    }

    // The same signing path admits a valid catalog, so each refusal above is about content.
    let second = versioned("1.1.0");
    let second_archive = fixture.package(&second);
    let valid = document(2, vec![original, signed(&second, &second_archive)], vec![]);
    let mut served = fixture.files.clone();
    served.extend(relink(&next, &serde_json::to_vec(&valid).unwrap(), None));
    let accepted_catalog = refresh(&fixture.installer, &served, now()).unwrap();
    let published: Value = serde_json::from_slice(accepted_catalog.catalog_bytes()).unwrap();
    assert_eq!(published, valid);
}

#[test]
fn flipped_role_signatures_leave_the_accepted_catalog_unchanged() {
    let fixture = Fixture::new();
    let next = update(&fixture.files, document(2, vec![], vec![]), &Files::new());
    let bytes = catalog_bytes(&next);
    let checkpoint = fixture.checkpoint();
    for (role, _) in ROLE_SEEDS {
        let mut served = fixture.files.clone();
        served.extend(relink(&next, &bytes, Some(role)));
        let error = refresh(&fixture.installer, &served, now()).err().unwrap();
        assert_eq!(
            error.to_string(),
            format!("{role} was signed by 0 authorized keys, requires 1")
        );
        assert_eq!(fixture.checkpoint(), checkpoint, "{role}");
    }
    let mut served = fixture.files.clone();
    served.extend(relink(&next, &bytes, None));
    refresh(&fixture.installer, &served, now()).unwrap();
    assert_ne!(fixture.checkpoint(), checkpoint);
}

#[test]
fn published_tree_without_a_receipt_must_match_its_archive() {
    let mut fixture = Fixture::new();
    let accepted = versioned(VERSION);
    let archive = fixture.package(&accepted);
    let catalog = fixture.publish(vec![signed(&accepted, &archive)]);
    let staged = fixture
        .installer
        .prepare(&catalog, ID, VERSION, PackageSource::Catalog(None), |_| {
            Ok(archive.as_slice())
        })
        .unwrap();
    let receipt = fixture
        .store
        .path()
        .join("packages")
        .join(format!(".verified-v1-{}.json", staged.archive_sha256));
    let executable = staged.directory.join("bin/app");
    fs::remove_file(&receipt).unwrap();
    fs::write(&executable, b"colliding bytes").unwrap();

    let error = fixture
        .installer
        .recover(ID, VERSION, &staged.archive_sha256)
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "Staged package differs from its verified archive"
    );
    // The colliding tree is neither trusted nor replaced.
    assert_eq!(fs::read(&executable).unwrap(), b"colliding bytes");
    assert!(!receipt.exists());
    assert_eq!(fixture.workspaces(), Vec::<OsString>::new());

    fs::write(&executable, fixture_elf()).unwrap();
    let recovered = fixture
        .installer
        .recover(ID, VERSION, &staged.archive_sha256)
        .unwrap();
    assert_eq!(recovered.directory, staged.directory);
    assert!(receipt.is_file());
}

#[test]
fn republished_identity_cannot_replace_an_installed_package() {
    let mut fixture = Fixture::new();
    let before_release = fixture.files.clone();
    let accepted = versioned(VERSION);
    let archive = fixture.package(&accepted);
    let catalog = fixture.publish(vec![signed(&accepted, &archive)]);
    let staged = fixture
        .installer
        .prepare(&catalog, ID, VERSION, PackageSource::Catalog(None), |_| {
            Ok(archive.as_slice())
        })
        .unwrap();
    let receipt = fixture
        .store
        .path()
        .join("packages")
        .join(format!(".verified-v1-{}.json", staged.archive_sha256));

    // A divergent history signed with the same online keys publishes the installed version
    // again with other bytes. The publisher refuses that transition; the reader authenticates
    // only the TUF chain, so the recorded package identity must protect the installation.
    let mut divergent = before_release;
    let next = update(&divergent, document(2, vec![], vec![]), &Files::new());
    divergent.extend(next);
    let mut entries = entries(&accepted);
    entries[2] = Entry::file("LICENSE", 0o644, *b"Apache-2.0");
    let republished = compress(fixture.work.path(), &entries);
    assert_ne!(digest(&republished), staged.archive_sha256);
    let next = update(
        &divergent,
        document(3, vec![signed(&accepted, &republished)], vec![]),
        &Files::new(),
    );
    divergent.extend(next);
    let replacement = refresh(&fixture.installer, &divergent, now()).unwrap();

    let error = fixture
        .installer
        .recover(ID, VERSION, &staged.archive_sha256)
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "Package identity differs from the signed catalog"
    );
    let error = fixture
        .installer
        .prepare::<io::Empty>(
            &replacement,
            ID,
            VERSION,
            PackageSource::Catalog(Some(&staged.archive_sha256)),
            |_| panic!("a republished archive reached the download boundary"),
        )
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "Package identity differs from the signed catalog"
    );
    assert_eq!(
        fs::read(staged.directory.join("bin/app")).unwrap(),
        fixture_elf()
    );
    assert!(receipt.is_file());
    assert!(
        !fixture
            .store
            .path()
            .join("packages")
            .join(digest(&republished))
            .exists()
    );
}

/// Run `script` as `uid` with `path` as its positional parameter. Returns whether it succeeded
/// and its error output.
#[cfg(unix)]
fn as_app(uid: u32, data: &Path, script: &str, path: &Path) -> (bool, String) {
    use std::{os::unix::process::CommandExt, process::Command};
    let output = Command::new("/bin/sh")
        .arg("-c")
        .arg(script)
        .arg("app-identity")
        .arg(path)
        .uid(uid)
        .gid(uid)
        .current_dir(data)
        .env_clear()
        .output()
        .unwrap();
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// The app identity reads and executes its staged package, but writes only to its data
/// directory. The installer re-checks owner and mode of every staged entry before reuse.
#[cfg(unix)]
pub(super) fn check_app_identity_boundaries(
    installer: &Installer,
    store: &Path,
    data: &Path,
    uid: u32,
    staged: &crate::app_install::StagedPackage,
) {
    use std::os::unix::fs::{MetadataExt, PermissionsExt, chown};

    let package = &staged.directory;
    let archive = &staged.archive_sha256;
    let executable = package.join("bin/app");
    let (readable, error) = as_app(uid, data, r#"test -r "$1" && test -x "$1""#, &executable);
    let modes = executable
        .ancestors()
        .filter_map(|path| {
            let metadata = fs::metadata(path).ok()?;
            Some(format!(
                "{} {:o} {}",
                path.display(),
                metadata.mode() & 0o7777,
                metadata.uid()
            ))
        })
        .collect::<Vec<_>>();
    assert!(readable, "{error} {modes:?}");
    let create = r#": > "$1""#;
    for (script, path) in [
        (r#"printf x >> "$1""#, executable.clone()),
        (create, package.join("unrecorded")),
        (create, package.join("api/unrecorded")),
        (r#"mv "$1" "$1.moved""#, package.join("api/openapi.json")),
        (r#"rm -f "$1""#, package.join("app.json")),
        (create, store.join("packages/unrecorded")),
        (create, store.join("archives").join(archive)),
        (create, store.join(CHECKPOINT)),
        (create, store.join("unrecorded")),
    ] {
        let (written, error) = as_app(uid, data, script, &path);
        assert!(
            !written && error.contains("Permission denied"),
            "{}: {error}",
            path.display()
        );
    }
    let allowed = data.join("identity-probe");
    let (written, error) = as_app(uid, data, r#"printf x > "$1""#, &allowed);
    assert!(written, "{error}");
    assert_eq!(fs::metadata(&allowed).unwrap().uid(), uid);
    fs::remove_file(allowed).unwrap();

    let app_id = staged.manifest["id"].as_str().unwrap();
    let version = staged.manifest["version"].as_str().unwrap();
    let recover = || installer.recover(app_id, version, archive);
    assert_eq!(&recover().unwrap().directory, package);
    let drift = "Staged package differs from its verified archive";
    chown(&executable, Some(uid), Some(uid)).unwrap();
    assert_eq!(recover().unwrap_err().to_string(), drift);
    chown(&executable, Some(0), Some(0)).unwrap();
    for (path, drifted, recorded) in [
        (package.join("api"), 0o775, 0o755),
        (package.join("api/openapi.json"), 0o664, 0o644),
        (executable.clone(), 0o4755, 0o755),
    ] {
        fs::set_permissions(&path, fs::Permissions::from_mode(drifted)).unwrap();
        assert_eq!(
            recover().unwrap_err().to_string(),
            drift,
            "{}",
            path.display()
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(recorded)).unwrap();
    }
    assert_eq!(&recover().unwrap().directory, package);
}

#[cfg(unix)]
#[test]
fn app_identity_writes_only_its_data_directory() {
    use std::os::unix::fs::{PermissionsExt, chown};

    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    const UID: u32 = 20_124;
    // The isolated test container mounts /tmp without exec permission, /run with it.
    let mut fixture = Fixture::with_store(tempfile::tempdir_in("/run").unwrap());
    let store = fixture.store.path().to_owned();
    fs::set_permissions(&store, fs::Permissions::from_mode(0o711)).unwrap();
    let accepted = versioned(VERSION);
    let archive = fixture.package(&accepted);
    let catalog = fixture.publish(vec![signed(&accepted, &archive)]);
    let staged = fixture
        .installer
        .prepare(&catalog, ID, VERSION, PackageSource::Catalog(None), |_| {
            Ok(archive.as_slice())
        })
        .unwrap();
    let data = tempfile::tempdir_in("/run").unwrap();
    chown(data.path(), Some(UID), Some(UID)).unwrap();
    check_app_identity_boundaries(&fixture.installer, &store, data.path(), UID, &staged);
}
