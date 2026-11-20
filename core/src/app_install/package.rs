use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
};

use marketplace_app_pipeline::package::execute;
use marketplace_artifacts::{
    FileIdentity, StreamVerification, file_identity, invalid, parse_json, read_file,
    validate_wire_json, verify_stream,
};
use rentnerproxy_app_contracts::{DownloadAsset, Package};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::filesystem;

const COMPRESSED_LIMIT: u64 = 257 * 1024 * 1024;
const RECEIPT_LIMIT: u64 = 64 * 1024 * 1024;
const DOWNLOAD_WORKSPACE: &str = ".download-";
const PACKAGE_WORKSPACE: &str = ".stage-";
pub(crate) const UI_ASSET_LIMIT: u64 = 8 * 1024 * 1024;
pub(crate) const UI_DOCUMENT_LIMIT: u64 = 4 * 1024 * 1024;

// Bump the receipt filename version when the package verification rules change.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Receipt {
    archive: FileIdentity,
    manifest_sha256: String,
    target: String,
    tree_sha256: [u8; 32],
    linkage: Value,
}

pub(super) fn stage<R: Read>(
    store: &Path,
    package: &Package<'_>,
    target: &str,
    allow_cache_replacement: bool,
    fetch: impl FnOnce(&DownloadAsset<'_>) -> io::Result<R>,
) -> io::Result<PathBuf> {
    let asset = package.release_assets().archive;
    if !(1..=COMPRESSED_LIMIT).contains(&asset.size_bytes) {
        return Err(invalid("Package exceeds the local compressed size limit"));
    }
    let archives = store.join("archives");
    let packages = store.join("packages");
    filesystem::directory(&archives, 0o700)?;
    filesystem::directory(&packages, 0o711)?;
    filesystem::clean_workspaces(&archives, DOWNLOAD_WORKSPACE)?;
    filesystem::clean_workspaces(&packages, PACKAGE_WORKSPACE)?;
    let archive = archives.join(asset.sha256);
    let identity = FileIdentity {
        sha256: asset.sha256.to_owned(),
        size_bytes: asset.size_bytes,
    };
    let download_required = match fs::symlink_metadata(&archive) {
        Ok(metadata) if metadata.is_file() => match verify_archive(&archive, &identity) {
            Ok(()) => false,
            Err(error) if allow_cache_replacement && error.kind() == io::ErrorKind::InvalidData => {
                true
            }
            Err(error) => return Err(error),
        },
        Ok(_) => return Err(invalid("Invalid cached archive file")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => true,
        Err(error) => return Err(error),
    };
    if download_required {
        let download = filesystem::private_workspace(&archives, DOWNLOAD_WORKSPACE)?;
        let incomplete = download.path().join("archive");
        write_download(fetch(&asset)?, &incomplete, &identity)?;
        fs::rename(&incomplete, &archive)?;
    } else {
        filesystem::sync_file(&archive)?;
    }
    filesystem::sync_directory(&archives)?;

    let destination = packages.join(asset.sha256);
    let receipt_path = packages.join(format!(".verified-v1-{}.json", asset.sha256));
    let published = match fs::symlink_metadata(&destination) {
        Ok(metadata) if metadata.is_dir() => true,
        Ok(_) => return Err(invalid("Invalid staged package directory")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(error),
    };
    // A protected receipt was written by the installer after verifying this signed archive.
    if published && let Some(receipt) = read_receipt(&receipt_path)? {
        if receipt.archive != identity
            || receipt.manifest_sha256 != package.manifest_sha256()
            || receipt.target != target
            || filesystem::tree_digest(&destination)? != receipt.tree_sha256
        {
            return Err(invalid("Staged package differs from its verified archive"));
        }
        verify_ui_package(&destination, package.manifest())?;
        verify_abi(&receipt.linkage, target)?;
        filesystem::sync_directory(&packages)?;
        return Ok(destination);
    }
    let work = filesystem::private_workspace(&packages, PACKAGE_WORKSPACE)?;
    let tar = work.path().join("package.tar");
    let tree = work.path().join("tree");
    execute(
        "decompress-package",
        json!({"inputPath": archive, "outputPath": tar}),
    )?;
    let checked = execute(
        "validate-package",
        json!({
            "archivePath": tar, "outputDirectory": tree, "target": target,
            "source": {"repositoryId":package.manifest()["source"]["repositoryId"], "commit":package.manifest()["source"]["commit"]}
        }),
    )?;
    if checked["manifestSha256"] != package.manifest_sha256()
        || !same_manifest(&checked["manifest"], package.manifest())
    {
        return Err(invalid("Packaged manifest differs from the signed catalog"));
    }
    verify_ui_package(&tree, package.manifest())?;
    verify_abi(&checked["linkage"], target)?;
    filesystem::sync_tree(&tree)?;
    let tree_sha256 = filesystem::tree_digest(&tree)?;
    if published {
        if filesystem::tree_digest(&destination)? != tree_sha256 {
            return Err(invalid("Staged package differs from its verified archive"));
        }
    } else {
        execute(
            "promote-package",
            json!({"stagingPath": tree, "outputDirectory": destination}),
        )?;
    }
    let receipt = Receipt {
        archive: identity,
        manifest_sha256: package.manifest_sha256().to_owned(),
        target: target.to_owned(),
        tree_sha256,
        linkage: checked["linkage"].clone(),
    };
    let mut receipt_file = tempfile::NamedTempFile::new_in(work.path())?;
    serde_json::to_writer(receipt_file.as_file_mut(), &receipt)?;
    if receipt_file.as_file().metadata()?.len() <= RECEIPT_LIMIT {
        receipt_file.as_file().sync_all()?;
        receipt_file
            .persist(receipt_path)
            .map_err(|error| error.error)?;
    }
    filesystem::sync_directory(&packages)?;
    Ok(destination)
}

fn verify_ui_package(directory: &Path, manifest: &Value) -> io::Result<()> {
    if manifest.get("ui").is_none() {
        return Ok(());
    }
    // The package validator has checked the relative paths and extracted entries.
    // Cached trees are checked against the protected receipt before reaching here.
    let api = manifest["api"]
        .as_str()
        .ok_or_else(|| invalid("UI package requires an OpenAPI document"))?;
    parse_ui_api(&read_file(&directory.join(api), UI_DOCUMENT_LIMIT)?)?;
    verify_ui_assets(&directory.join("ui"))
}

fn verify_ui_assets(directory: &Path) -> io::Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            verify_ui_assets(&entry.path())?;
        } else if !metadata.is_file() || metadata.len() > UI_ASSET_LIMIT {
            return Err(invalid(
                "UI assets must be regular files no larger than 8 MiB",
            ));
        }
    }
    Ok(())
}

pub(crate) fn parse_ui_api(bytes: &[u8]) -> io::Result<Value> {
    let api = parse_json(bytes)?;
    validate_wire_json(&api)?;
    let patch = api["openapi"]
        .as_str()
        .and_then(|version| version.strip_prefix("3.1."));
    if !patch.is_some_and(|patch| {
        (1..=3).contains(&patch.len()) && patch.bytes().all(|byte| byte.is_ascii_digit())
    }) {
        return Err(invalid("UI packages require OpenAPI 3.1"));
    }
    Ok(api)
}

pub(super) fn write_download(
    source: impl Read,
    destination: &Path,
    identity: &FileIdentity,
) -> io::Result<()> {
    if verify_stream(source, identity, Some(destination))? != StreamVerification::Verified {
        return Err(invalid(
            "Compressed package differs from its signed identity",
        ));
    }
    filesystem::sync_file(destination)
}

fn verify_archive(path: &Path, identity: &FileIdentity) -> io::Result<()> {
    if &file_identity(path, identity.size_bytes)? != identity {
        return Err(invalid("Cached archive differs from the signed release"));
    }
    Ok(())
}

fn read_receipt(path: &Path) -> io::Result<Option<Receipt>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !metadata.is_file() {
        return Err(invalid("Invalid package verification receipt"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o7777 != 0o600 {
            return Err(invalid("Invalid package verification receipt"));
        }
    }
    Ok(Some(serde_json::from_slice(&read_file(
        path,
        RECEIPT_LIMIT,
    )?)?))
}

fn same_manifest(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Number(a), Value::Number(b)) => a.as_f64() == b.as_f64(),
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(a, b)| same_manifest(a, b))
        }
        (Value::Object(a), Value::Object(b)) => {
            a.len() == b.len()
                && a.iter()
                    .all(|(key, a)| b.get(key).is_some_and(|b| same_manifest(a, b)))
        }
        _ => left == right,
    }
}

#[derive(Deserialize)]
struct Linkage {
    needed: Vec<String>,
    interpreter: Option<PathBuf>,
}

pub(super) fn verify_abi(linkage: &Value, target: &str) -> io::Result<()> {
    let executables: Vec<Linkage> = serde_json::from_value(linkage.clone())?;
    let platform = match target {
        "linux-amd64" => "x86_64-linux-gnu",
        "linux-arm64" => "aarch64-linux-gnu",
        _ => return Err(invalid("Unsupported package ABI")),
    };
    let directory = Path::new("/usr/lib").join(platform);
    let mut libraries = BTreeSet::new();
    for executable in executables {
        libraries.extend(executable.needed);
        if let Some(loader) = executable.interpreter {
            let file = loader
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| invalid("Invalid ELF interpreter"))?;
            if fs::canonicalize(&loader)? != fs::canonicalize(directory.join(file))? {
                return Err(invalid(
                    "ELF interpreter differs from the appliance interpreter",
                ));
            }
            libraries.insert(file.to_owned());
        }
    }
    let mut versions = BTreeMap::new();
    for library in libraries {
        if library.contains('\\')
            || Path::new(&library)
                .file_name()
                .and_then(|name| name.to_str())
                != Some(library.as_str())
        {
            return Err(invalid("ELF dependency must name an appliance library"));
        }
        let path = fs::canonicalize(directory.join(&library))?;
        filesystem::check_root_path(&path, false)?;
        let definitions = execute(
            "inspect-appliance-library",
            json!({"inputPath": path, "library": library}),
        )?;
        versions.insert(library, definitions);
    }
    execute(
        "verify-package-abi",
        json!({"linkage": linkage, "applianceLibraryVersions": versions}),
    )?;
    Ok(())
}
