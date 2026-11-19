use std::{
    collections::{BTreeMap, BTreeSet},
    fs, io,
    path::{Path, PathBuf},
};

use marketplace_app_pipeline::package::execute;
use marketplace_artifacts::{FileIdentity, file_identity, invalid};
use rentnerproxy_app_contracts::{DownloadAsset, Package};
use serde::Deserialize;
use serde_json::{Value, json};

use super::filesystem;

const COMPRESSED_LIMIT: u64 = 257 * 1024 * 1024;

pub(super) fn stage(
    store: &Path,
    package: &Package<'_>,
    target: &str,
    fetch: impl FnOnce(&DownloadAsset<'_>, &Path) -> io::Result<()>,
) -> io::Result<PathBuf> {
    let asset = package.release_assets().archive;
    if !(1..=COMPRESSED_LIMIT).contains(&asset.size_bytes) {
        return Err(invalid("Package exceeds the local compressed size limit"));
    }
    let archives = store.join("archives");
    let packages = store.join("packages");
    filesystem::directory(&archives, 0o700)?;
    filesystem::directory(&packages, 0o711)?;
    let archive = archives.join(asset.sha256);
    match fs::symlink_metadata(&archive) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fetch(&asset, &archive)?;
            filesystem::sync_file(&archive)?;
            filesystem::sync_directory(&archives)?;
        }
        Err(error) => return Err(error),
    }
    let identity = FileIdentity {
        sha256: asset.sha256.to_owned(),
        size_bytes: asset.size_bytes,
    };
    if file_identity(&archive, asset.size_bytes)? != identity {
        return Err(invalid("Cached archive differs from the signed release"));
    }
    let mut builder = tempfile::Builder::new();
    builder.prefix(".stage-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(fs::Permissions::from_mode(0o700));
    }
    let work = builder.tempdir_in(&packages)?;
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
    verify_abi(&checked["linkage"], target)?;
    filesystem::sync_tree(&tree)?;
    let destination = packages.join(asset.sha256);
    match fs::symlink_metadata(&destination) {
        Ok(_) => filesystem::compare_tree(&tree, &destination)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            execute(
                "promote-package",
                json!({"stagingPath": tree, "outputDirectory": destination}),
            )?;
        }
        Err(error) => return Err(error),
    }
    filesystem::sync_directory(&packages)?;
    Ok(destination)
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
