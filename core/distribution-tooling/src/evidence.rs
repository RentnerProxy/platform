use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Write};
use std::path::Path;

use marketplace_artifacts::{digest, file_identity, invalid, read_file};
use serde::{Deserialize, Serialize};

use crate::{BUNDLE_BYTES, decode};

const MAX_FILES: usize = 4096;
const SMALL_JSON: u64 = 4096;
const MAX_RUN_ATTEMPT: u64 = 9_007_199_254_740_991;
const MAX_OCI_ARCHIVE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_IMAGE_EVIDENCE_BYTES: u64 = 1024 * 1024;

#[derive(Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
struct Identity {
    revision: String,
    version: String,
    digest: String,
    run_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Workflow {
    #[serde(flatten)]
    identity: Identity,
    run_attempt: u64,
}

impl Workflow {
    fn allows(&self, expected: &Self) -> bool {
        self.identity == expected.identity
            && (1..=MAX_RUN_ATTEMPT).contains(&expected.run_attempt)
            && (1..=expected.run_attempt).contains(&self.run_attempt)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Reports {
    identity: Workflow,
    candidate_bundle_sha256: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OciInput {
    archive_sha256: String,
    evidence_sha256: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Report {
    schema_version: u32,
    #[serde(flatten)]
    workflow: Workflow,
    target: String,
    architecture: String,
    passed: bool,
    candidate_bundle_sha256: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Binding {
    schema_version: u32,
    status: String,
    candidate_bundle_sha256: String,
    image_evidence_sha256: String,
}

#[derive(Deserialize)]
struct ManifestFile {
    file: String,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    schema_version: u32,
    #[serde(flatten)]
    workflow: Workflow,
    files: Vec<ManifestFile>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Candidate {
    schema_version: u32,
    #[serde(flatten)]
    workflow: Workflow,
    status: String,
    archive_sha256: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImageEvidence {
    schema_version: u32,
    #[serde(flatten)]
    identity: Identity,
    native: [serde_json::Value; 2],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BoundEvidence {
    candidate_bundle_sha256: String,
    image_evidence: serde_json::Value,
}

fn sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn verify_oci_input(root: &Path, expected: OciInput, output: impl Write) -> io::Result<()> {
    if !sha256(&expected.archive_sha256)
        || file_identity(&root.join("candidate-image.tar"), MAX_OCI_ARCHIVE_BYTES)?.sha256
            != expected.archive_sha256
    {
        return Err(invalid("Candidate image archive checksum mismatch"));
    }
    if let Some(sha) = expected.evidence_sha256 {
        let evidence = read_file(&root.join("evidence.json"), MAX_IMAGE_EVIDENCE_BYTES)?;
        if !sha256(&sha) || digest(&evidence) != sha {
            return Err(invalid("Assessed image evidence checksum mismatch"));
        }
        let parsed: serde_json::Value = decode(&evidence)?;
        serde_json::to_writer(output, &parsed).map_err(io::Error::other)?;
    }
    Ok(())
}

fn files(root: &Path) -> io::Result<BTreeSet<String>> {
    fn visit(
        directory: &Path,
        prefix: &str,
        depth: usize,
        remaining: &mut usize,
        files: &mut BTreeSet<String>,
    ) -> io::Result<()> {
        if depth > 32 || !fs::symlink_metadata(directory)?.is_dir() {
            return Err(invalid("Invalid distribution artifact directory"));
        }
        for entry in fs::read_dir(directory)? {
            *remaining = remaining
                .checked_sub(1)
                .ok_or_else(|| invalid("Artifact bundle is too large"))?;
            let entry = entry?;
            let name = entry.file_name();
            let name = name
                .to_str()
                .filter(|name| {
                    !matches!(*name, "" | "." | "..")
                        && name.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')
                        })
                })
                .ok_or_else(|| invalid("Invalid artifact path"))?;
            let kind = entry.file_type()?;
            if kind.is_dir() {
                visit(
                    &entry.path(),
                    &format!("{prefix}{name}/"),
                    depth + 1,
                    remaining,
                    files,
                )?;
            } else if kind.is_file() {
                files.insert(format!("{prefix}{name}"));
            } else {
                return Err(invalid("Artifact links are forbidden"));
            }
        }
        Ok(())
    }
    let mut paths = BTreeSet::new();
    let mut remaining = MAX_FILES;
    visit(root, "", 0, &mut remaining, &mut paths)?;
    Ok(paths)
}

pub fn verify_reports(root: &Path, expected: Reports) -> io::Result<()> {
    if !sha256(&expected.candidate_bundle_sha256) {
        return Err(invalid("Invalid candidate bundle checksum"));
    }
    let mut paths = files(root)?;
    for architecture in ["amd64", "arm64"] {
        for target in ["debian", "fedora"] {
            let name = format!("native-{target}-{architecture}.json");
            paths.remove(&name);
            let report: Report = decode(&read_file(&root.join(name), SMALL_JSON)?)
                .map_err(|_| invalid("Missing or mismatched native distribution gate"))?;
            if report.schema_version != 1
                || !report.workflow.allows(&expected.identity)
                || report.target != target
                || report.architecture != architecture
                || !report.passed
                || report.candidate_bundle_sha256 != expected.candidate_bundle_sha256
            {
                return Err(invalid("Missing or mismatched native distribution gate"));
            }
        }
    }
    if !paths.is_empty() {
        return Err(invalid("Unexpected native distribution reports"));
    }
    Ok(())
}

pub fn verify_bound(root: &Path, expected: Workflow, output: impl Write) -> io::Result<()> {
    let mut paths = files(root)?;
    for excluded in [
        "bundle.json",
        "candidate-bundle.json",
        "binding.json",
        "image-evidence.json",
    ] {
        paths.remove(excluded);
    }
    let binding: Binding = decode(&read_file(&root.join("binding.json"), SMALL_JSON)?)?;
    let manifest = read_file(&root.join("candidate-bundle.json"), BUNDLE_BYTES)?;
    let image = read_file(&root.join("image-evidence.json"), MAX_IMAGE_EVIDENCE_BYTES)?;
    if binding.schema_version != 1
        || binding.status != "assessed"
        || binding.candidate_bundle_sha256 != digest(&manifest)
        || binding.image_evidence_sha256 != digest(&image)
    {
        return Err(invalid("Invalid assessed distribution binding"));
    }
    let manifest: Manifest = decode(&manifest)?;
    if manifest.schema_version != 1 || !manifest.workflow.allows(&expected) {
        return Err(invalid("Distribution candidate proof identity mismatch"));
    }
    if paths.len() != manifest.files.len() {
        return Err(invalid("Unexpected bound distribution files"));
    }
    let candidate = read_file(&root.join("image-candidate.json"), BUNDLE_BYTES)?;
    for (path, file) in paths.iter().zip(manifest.files) {
        if *path != file.file {
            return Err(invalid("Bound package bytes changed"));
        }
        let sha = if path == "image-candidate.json" {
            digest(&candidate)
        } else {
            file_identity(&root.join(path), BUNDLE_BYTES)?.sha256
        };
        if sha != file.sha256 {
            return Err(invalid("Bound package bytes changed"));
        }
    }
    let candidate: Candidate = decode(&candidate)?;
    if candidate.schema_version != 1
        || candidate.status != "unassessed"
        || !candidate.workflow.allows(&expected)
        || !sha256(&candidate.archive_sha256)
    {
        return Err(invalid(
            "Unassessed distribution candidate identity mismatch",
        ));
    }
    let image_evidence = marketplace_artifacts::parse_json(&image)?;
    let image: ImageEvidence = serde_json::from_value(image_evidence.clone())
        .map_err(|_| invalid("Invalid assessed image evidence"))?;
    if image.schema_version != 1
        || image.identity != expected.identity
        || !image.native.iter().all(serde_json::Value::is_object)
    {
        return Err(invalid("Invalid assessed image evidence"));
    }
    serde_json::to_writer(
        output,
        &BoundEvidence {
            candidate_bundle_sha256: binding.candidate_bundle_sha256,
            image_evidence,
        },
    )
    .map_err(io::Error::other)
}
