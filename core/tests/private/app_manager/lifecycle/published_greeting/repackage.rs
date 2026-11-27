//! Signed Greeting releases repackaged from the official 1.0.1 archive.
//!
//! Each release clones the official manifest with its own version and manifest fields, and packs
//! the official files with files of its own. Each release gets its own catalog revision, because
//! only the latest newer release is offered, and a manager restart refreshes the listing.

use super::distribution::Distribution;
use super::*;
use crate::app_install::tests::pack_fixture_archive;
use crate::app_install::tests::published_greeting::{PublishedGreeting, PublishedSnapshot};
use marketplace_app_pipeline::package::execute;
use marketplace_artifacts::{digest, file_identity};
use rentnerproxy_app_contracts::Contracts;
use time::OffsetDateTime;

/// One repackaged release: its version, the manifest fields it sets and the files it adds.
pub(super) struct Repackaged {
    pub version: &'static str,
    pub fields: Value,
    pub files: Vec<(String, Vec<u8>)>,
}

pub(super) fn native_target() -> &'static str {
    if cfg!(target_arch = "x86_64") {
        "linux-amd64"
    } else {
        "linux-arm64"
    }
}

fn manifest(official: &Value, version: &str, fields: &Value) -> Value {
    let mut manifest = official.clone();
    manifest["version"] = version.into();
    for (field, value) in fields.as_object().unwrap() {
        manifest[field] = value.clone();
    }
    manifest
}

/// Extract the verified official archive once with the installer's package validator.
fn official_tree(archive: &Path, work: &Path, source: &Value) -> PathBuf {
    let tar = work.join("official.tar");
    let tree = work.join("official");
    execute(
        "decompress-package",
        json!({"inputPath": archive, "outputPath": tar}),
    )
    .unwrap();
    execute(
        "validate-package",
        json!({
            "archivePath": tar,
            "outputDirectory": tree,
            "target": native_target(),
            "source": {"repositoryId": source["repositoryId"], "commit": source["commit"]},
        }),
    )
    .unwrap();
    fs::remove_file(tar).unwrap();
    tree
}

/// Package-relative paths and archive modes of every file below `directory`.
fn package_files(root: &Path, directory: &Path, files: &mut Vec<(String, usize)>) {
    for entry in fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        let metadata = fs::symlink_metadata(&path).unwrap();
        if metadata.is_dir() {
            package_files(root, &path, files);
            continue;
        }
        assert!(metadata.is_file(), "{}", path.display());
        let relative = path
            .strip_prefix(root)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let mode = if metadata.permissions().mode() & 0o111 == 0 {
            0o644
        } else {
            0o755
        };
        files.push((relative, mode));
    }
}

/// Repack the official package with `manifest` as app.json and the release's own files.
fn pack(
    work: &Path,
    tree: &Path,
    files: &[(String, usize)],
    manifest: &Value,
    own: &[(String, Vec<u8>)],
) -> PathBuf {
    let directory = work.join(format!(
        "greeting-{}",
        manifest["version"].as_str().unwrap()
    ));
    fs::create_dir(&directory).unwrap();
    let archive = pack_fixture_archive(
        &directory,
        std::iter::once(("app.json", 0o644, serde_json::to_vec(manifest).unwrap()))
            .chain(
                files
                    .iter()
                    .map(|(path, mode)| (path.as_str(), *mode, fs::read(tree.join(path)).unwrap())),
            )
            .chain(
                own.iter()
                    .map(|(path, bytes)| (path.as_str(), 0o644, bytes.clone())),
            ),
    );
    // Only the compressed archive is served.
    fs::remove_file(directory.join("fixture.tar")).unwrap();
    archive
}

/// Clone the official release as `version`. The native package names the repacked archive.
/// No archive exists for the other target, so it gets an identity no asset can satisfy.
fn release_entry(official: &Value, version: &str, fields: &Value, archive: &Value) -> Value {
    let mut release = official.clone();
    release["version"] = version.into();
    for package in release["packages"].as_array_mut().unwrap() {
        let manifest = manifest(&package["manifest"], version, fields);
        package["manifestSha256"] = digest(&serde_json::to_vec(&manifest).unwrap()).into();
        if manifest["target"] == native_target() {
            package["archive"] = archive.clone();
        } else {
            let identity = format!("unpublished {APP_ID} {version} {}", manifest["target"]);
            package["archive"]["sha256"] = digest(identity.as_bytes()).into();
        }
        package["manifest"] = manifest;
    }
    release
}

/// Repackage `releases` and sign one catalog revision for each, in order.
pub(super) fn repackage<const N: usize>(
    fixture: &mut PublishedGreeting,
    work: &Path,
    releases: &[Repackaged; N],
) -> [PublishedSnapshot; N] {
    let official = &fixture.snapshots[1];
    let (official_version, official_commit) = (official.version, official.official_commit);
    let official_archive = official.archive_path.clone();
    let mut catalog: Value = serde_json::from_slice(fixture.repository.catalog_bytes()).unwrap();
    let base = catalog["releases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|release| release["appId"] == APP_ID && release["version"] == official_version)
        .expect("official Greeting 1.0.1 release")
        .clone();
    let native = base["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|package| package["manifest"]["target"] == native_target())
        .expect("official native Greeting package")["manifest"]
        .clone();
    let tree = official_tree(&official_archive, work, &native["source"]);
    let mut files = Vec::new();
    package_files(&tree, &tree, &mut files);
    files.retain(|(path, _)| path != "app.json");
    files.sort_unstable();
    let contracts = Contracts::new().unwrap();
    let signed_at = OffsetDateTime::now_utc().replace_nanosecond(0).unwrap();
    let snapshots = std::array::from_fn(|index| {
        let Repackaged {
            version,
            fields,
            files: own,
        } = &releases[index];
        let archive_path = pack(
            work,
            &tree,
            &files,
            &manifest(&native, version, fields),
            own,
        );
        let identity =
            file_identity(&archive_path, fs::metadata(&archive_path).unwrap().len()).unwrap();
        let archive = json!({"sha256": identity.sha256, "sizeBytes": identity.size_bytes});
        catalog["releases"]
            .as_array_mut()
            .unwrap()
            .push(release_entry(&base, version, fields, &archive));
        let catalog_revision = catalog["revision"].as_u64().unwrap() + 1;
        catalog["revision"] = catalog_revision.into();
        let bytes = serde_json::to_vec(&catalog).unwrap();
        let signed = fixture.repository.publish(&bytes, signed_at).clone();
        let validated = contracts.validate_catalog(&catalog).unwrap();
        let package = validated
            .package(APP_ID, version, native_target())
            .expect("repackaged native Greeting package");
        let asset = package.release_assets().archive;
        assert_eq!(asset.sha256, identity.sha256);
        PublishedSnapshot {
            version,
            official_commit,
            catalog_revision,
            catalog_sha256: digest(&bytes),
            files: signed,
            archive_path,
            archive_url: asset.url,
            archive_sha256: identity.sha256,
            archive_size_bytes: identity.size_bytes,
            manifest_sha256: package.manifest_sha256().to_owned(),
        }
    });
    fs::remove_dir_all(tree).unwrap();
    snapshots
}

pub(super) fn installation<'a>(view: &'a Value, id: &str) -> &'a Value {
    view["installations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["installationId"] == id)
        .expect("Greeting installation in the catalog view")
}

/// Serve the revision that adds `release` and restart the manager, which refreshes its listing
/// on start. Returns the running installation, which must offer exactly that release.
pub(super) async fn offer(
    hosts: &Distribution,
    release: &PublishedSnapshot,
    manager: &mut Child,
    controller: &Path,
    installer: &InstallerFixture,
    id: &str,
) -> Value {
    hosts.serve_metadata(release.files.clone());
    halt(manager).await;
    *manager = start_manager(controller, &installer.config, &installer.token, Some(id)).await;
    let ready = wait_catalog_state("ready").await;
    let row = running_installation(&ready, id).clone();
    assert_eq!(
        row["update"],
        json!({"version": release.version, "archiveSha256": release.archive_sha256}),
        "{row}"
    );
    row
}

pub(super) fn generation(row: &Value) -> u64 {
    row["generation"].as_u64().unwrap()
}
