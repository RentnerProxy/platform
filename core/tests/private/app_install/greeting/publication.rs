use std::{
    fs::{self, File},
    io,
    path::{Path, PathBuf},
};

use rentnerproxy_app_catalog::{ReadOptions, UpdateOptions, read_catalog, update_catalog};
use rentnerproxy_app_contracts::{Contracts, DownloadAsset};
use rentnerproxy_app_pipeline::{evidence, package, publication};
use rentnerproxy_artifacts::digest;
use serde_json::{Value, json};

use super::super::{Files, PIN, keys, now, pack_fixture_archive};
use super::ID;

const TARGETS: [&str; 2] = ["linux-amd64", "linux-arm64"];
const PACKAGE_FILES: [&str; 7] = [
    "app.json",
    "bin/app",
    "LICENSE",
    "api/openapi.json",
    "ui/index.html",
    "ui/app.js",
    "ui/app.css",
];
const RELEASE_URL: &str = "https://github.com/RentnerProxy/app-catalog/releases/download/";

pub(super) struct Candidate {
    directory: PathBuf,
    handoff: Value,
    pub(super) approval: Value,
}

fn archive_name(version: &str, target: &str) -> String {
    format!("{ID}-{version}-{target}.tar.zst")
}

impl Candidate {
    pub(super) fn seal(fixture: &Path, work: &Path, version: &str, run: &str) -> Self {
        fs::create_dir(work).unwrap();
        let manifest: Value =
            serde_json::from_slice(&fs::read(fixture.join(TARGETS[0]).join("app.json")).unwrap())
                .unwrap();
        let source = &manifest["source"];
        let build = json!({
            "repositoryId": source["repositoryId"],
            "workflowCommit": source["commit"],
            "workflowPath": ".github/workflows/app-candidate.yml",
            "runId": run,
            "attempt": 1,
        });
        let sbom = work.join("fixture-sbom.json");
        fs::write(
            &sbom,
            json!({
                "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                "components": [{"type": "application", "name": ID, "version": version}],
            })
            .to_string(),
        )
        .unwrap();
        for target in TARGETS {
            let input = fixture.join(target);
            let temp = tempfile::tempdir_in(work).unwrap();
            let archive = pack_fixture_archive(
                temp.path(),
                PACKAGE_FILES.into_iter().map(|path| {
                    let mode = if path == "bin/app" { 0o755 } else { 0o644 };
                    (path, mode, fs::read(input.join(path)).unwrap())
                }),
            );
            let checked = package::execute(
                "validate-package",
                json!({
                    "archivePath": temp.path().join("fixture.tar"),
                    "outputDirectory": temp.path().join("validated"),
                    "target": target, "source": source,
                }),
            )
            .unwrap();
            assert_eq!(checked["manifest"]["id"], ID);
            assert_eq!(checked["manifest"]["version"], version);
            evidence::execute(
                "seal-target",
                json!({
                    "outputDirectory": work.join(target),
                    "archivePath": archive, "sbomPath": sbom,
                    "manifest": checked["manifest"], "manifestSha256": checked["manifestSha256"],
                    "build": build, "purpose": "candidate",
                    "applianceImage": format!("fixture.invalid/greeting@sha256:{}", "5".repeat(64)),
                }),
            )
            .unwrap();
        }
        let directory = work.join("sealed");
        let sealed = evidence::execute(
            "seal-candidate",
            json!({
                "outputDirectory": directory,
                "targetDirectories": {
                    "linux-amd64": work.join("linux-amd64"),
                    "linux-arm64": work.join("linux-arm64"),
                },
                "source": source, "build": build, "purpose": "candidate",
                "publisherName": "Greeting integration fixture",
            }),
        )
        .unwrap();
        for target in TARGETS {
            fs::remove_dir_all(work.join(target)).unwrap();
        }
        let approval = json!({
            "formatVersion": 1, "id": format!("fixture-approval-{run}"), "revision": 1,
            "actorId": "fixture-reviewer", "approvedAt": "2026-11-01T12:00:00.000Z",
            "candidate": sealed,
        });
        // The receipt stands in for the authenticated GitHub artifact response.
        // Native handoff verification still reads and checks every sealed file.
        let receipt = json!({
            "id": run,
            "sha256": digest(&fs::read(directory.join("candidate.json")).unwrap()),
        });
        let mut artifact = receipt.clone();
        artifact["expiresAt"] = json!("2026-11-02T12:00:00.000Z");
        artifact["expired"] = json!(false);
        let handoff = json!({
            "directory": directory, "source": source, "build": build,
            "artifact": artifact, "downloadedArtifact": receipt,
            "now": now().unix_timestamp() * 1_000,
        });
        Self {
            directory,
            handoff,
            approval,
        }
    }

    pub(super) fn verify(&self, approval: &Value) -> io::Result<()> {
        let received = evidence::execute("verify-handoff", self.handoff.clone())?;
        Contracts::new()
            .and_then(|contracts| contracts.check_approval_binding(&received, approval))
            .map_err(io::Error::other)
    }

    pub(super) fn archive(&self, target: &str) -> PathBuf {
        self.directory.join(archive_name(self.version(), target))
    }

    pub(super) fn version(&self) -> &str {
        self.approval["candidate"]["release"]["version"]
            .as_str()
            .unwrap()
    }

    pub(super) fn publish(&self, files: &mut Files, releases: &Path) {
        self.verify(&self.approval).unwrap();
        let current = read_catalog(
            |path, _| Ok(files.get(path).cloned()),
            PIN,
            ReadOptions {
                now: now(),
                allow_expired_roles: false,
                next_root: None,
                previous: None,
            },
        )
        .unwrap();
        let catalog: Value = serde_json::from_slice(current.catalog_bytes()).unwrap();
        for (status, expected) in [("withdrawn", "idle"), ("approved", "publish")] {
            let action = publication::execute(
                "plan",
                json!({"catalog": catalog, "work": {"status": status, "approval": self.approval}}),
            )
            .unwrap();
            assert_eq!(action, expected);
        }
        let release = &self.approval["candidate"]["release"];
        let next = publication::execute("publish", json!({"catalog": catalog, "release": release}))
            .unwrap();
        let additions = update_catalog(
            &current,
            &serde_json::to_vec(&next).unwrap(),
            &keys(),
            UpdateOptions {
                now: now(),
                next_root: None,
                icons: &Files::new(),
            },
        )
        .unwrap();

        // Keep only approved release assets in the download tree. Expose the
        // corresponding catalog snapshot once every asset is available there.
        let destination = releases.join(format!("{ID}-v{}", self.version()));
        fs::create_dir(&destination).unwrap();
        for target in TARGETS {
            let archive = archive_name(self.version(), target);
            for name in [
                format!("{archive}.sbom.json"),
                format!("{archive}.provenance.json"),
                archive,
            ] {
                fs::copy(self.directory.join(&name), destination.join(name)).unwrap();
            }
        }
        files.extend(additions);
    }
}

pub(super) fn download(releases: &Path, asset: &DownloadAsset<'_>) -> io::Result<File> {
    let path = asset
        .url
        .strip_prefix(RELEASE_URL)
        .expect("signed asset must use the controlled distribution");
    File::open(releases.join(path))
}
