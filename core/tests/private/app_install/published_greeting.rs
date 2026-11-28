use std::{
    collections::BTreeMap,
    io,
    path::{Path, PathBuf},
};

use ed25519_dalek::{Signer, SigningKey, pkcs8::EncodePrivateKey};
use rentnerproxy_app_catalog::{
    CatalogError, ReadOptions, SigningKeys, TrustedCatalog, UpdateOptions, bootstrap_catalog,
    read_catalog, update_catalog,
};
use rentnerproxy_app_contracts::Contracts;
use rentnerproxy_artifacts::{FileIdentity, digest, file_identity, read_file};
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

use super::Files;

const ID: &str = "rentnerproxy.greeting";
const OFFICIAL_ROOT: &[u8] = include_bytes!("../../../../docker/production/apps/catalog/root.json");
const RELEASES: [(&str, &str, u64); 2] = [
    ("1.0.0", "44557b84bce0a63cb71aadc636f8a9c18efeea22", 2),
    ("1.0.1", "37bcec3118a244ff024e9d6f5d92806aeaa2fa0c", 3),
];

pub(crate) struct PublishedGreeting {
    pub root: Vec<u8>,
    pub snapshots: [PublishedSnapshot; 2],
    /// The throwaway repository that signed `snapshots`, for further revisions.
    pub repository: ReplayRepository,
}

pub(crate) struct PublishedSnapshot {
    pub version: &'static str,
    pub official_commit: &'static str,
    pub catalog_revision: u64,
    pub catalog_sha256: String,
    pub files: Files,
    pub archive_path: PathBuf,
    pub archive_url: String,
    pub archive_sha256: String,
    pub archive_size_bytes: u64,
    pub manifest_sha256: String,
}

fn official_catalog(
    directory: &Path,
    accepted_at: OffsetDateTime,
    previous: Option<&TrustedCatalog>,
) -> TrustedCatalog {
    read_catalog(
        |name, limit| {
            let path = directory.join(name);
            match read_file(&path, limit as u64) {
                Ok(bytes) => Ok(Some(bytes)),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(CatalogError::new(format!("{}: {error}", path.display()))),
            }
        },
        OFFICIAL_ROOT,
        ReadOptions {
            now: accepted_at,
            allow_expired_roles: false,
            next_root: None,
            previous,
        },
    )
    .unwrap_or_else(|error| {
        panic!(
            "Verifying official catalog {}: {error}",
            directory.display()
        )
    })
}

fn replay_trust(expires: OffsetDateTime) -> (Vec<u8>, SigningKeys) {
    let roles = ["root", "targets", "snapshot", "timestamp"];
    let signing = roles.map(|_| {
        let mut seed = [0; 32];
        aws_lc_rs::rand::fill(&mut seed).unwrap();
        SigningKey::from_bytes(&seed)
    });
    let mut descriptors = BTreeMap::new();
    let mut delegations = BTreeMap::new();
    for (role, key) in roles.into_iter().zip(&signing) {
        let public: String = key
            .verifying_key()
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let descriptor =
            json!({"keytype": "ed25519", "scheme": "ed25519", "keyval": {"public": public}});
        let key_id = digest(&serde_json::to_vec(&descriptor).unwrap());
        delegations.insert(role, json!({"threshold": 1, "keyids": [&key_id]}));
        descriptors.insert(key_id, descriptor);
    }
    let signed = json!({
        "_type": "root", "consistent_snapshot": true, "version": 1,
        "spec_version": "1.0.0", "expires": expires.format(&Rfc3339).unwrap(),
        "keys": descriptors, "roles": delegations,
    });
    // These ASCII-only fields serialize as sorted compact JSON, the canonical TUF wire form.
    let [root_key, targets, snapshot, timestamp] = &signing;
    let signature = root_key.sign(&serde_json::to_vec(&signed).unwrap());
    let root = serde_json::to_vec(&json!({
        "signed": signed,
        "signatures": [{"keyid": signed["roles"]["root"]["keyids"][0], "sig": format!("{signature:x}")}],
    }))
    .unwrap();
    let [targets, snapshot, timestamp] =
        [targets, snapshot, timestamp].map(|key| key.to_pkcs8_pem(Default::default()).unwrap());
    (
        root,
        SigningKeys::from_pem(&targets, &snapshot, &timestamp).unwrap(),
    )
}

fn read_replay(
    root: &[u8],
    files: &Files,
    at: OffsetDateTime,
    previous: Option<&TrustedCatalog>,
) -> TrustedCatalog {
    read_catalog(
        |name, _| Ok(files.get(name).cloned()),
        root,
        ReadOptions {
            now: at,
            allow_expired_roles: false,
            next_root: None,
            previous,
        },
    )
    .unwrap()
}

/// A throwaway TUF repository that re-signs verified catalog bytes under a test root.
pub(crate) struct ReplayRepository {
    root: Vec<u8>,
    keys: SigningKeys,
    files: Files,
    state: TrustedCatalog,
}

impl ReplayRepository {
    fn bootstrap(root_expires: OffsetDateTime, signed_at: OffsetDateTime) -> Self {
        let (root, keys) = replay_trust(root_expires);
        let files = bootstrap_catalog(&root, &keys, signed_at).unwrap();
        let state = read_replay(&root, &files, signed_at, None);
        Self {
            root,
            keys,
            files,
            state,
        }
    }

    pub(crate) fn catalog_bytes(&self) -> &[u8] {
        self.state.catalog_bytes()
    }

    fn sign_with_icons(&self, catalog: &[u8], icons: &Files, signed_at: OffsetDateTime) -> Files {
        let mut files = self.files.clone();
        let options = UpdateOptions {
            now: signed_at,
            next_root: None,
            icons,
        };
        files.extend(update_catalog(&self.state, catalog, &self.keys, options).unwrap());
        files
    }

    /// Sign the next catalog at `signed_at` without accepting it as repository state.
    /// Online roles expire relative to `signed_at`, so a past time yields expired metadata.
    pub(crate) fn sign(&self, catalog: &[u8], signed_at: OffsetDateTime) -> Files {
        self.sign_with_icons(catalog, &Files::new(), signed_at)
    }

    fn publish_with_icons(
        &mut self,
        catalog: &[u8],
        icons: &Files,
        signed_at: OffsetDateTime,
    ) -> &Files {
        let files = self.sign_with_icons(catalog, icons, signed_at);
        self.state = read_replay(&self.root, &files, signed_at, Some(&self.state));
        assert_eq!(self.state.catalog_bytes(), catalog);
        self.files = files;
        &self.files
    }

    /// Sign and accept the next catalog. Unchanged bytes renew only the due online roles.
    pub(crate) fn publish(&mut self, catalog: &[u8], signed_at: OffsetDateTime) -> &Files {
        self.publish_with_icons(catalog, &Files::new(), signed_at)
    }
}

/// Verify the immutable official catalog and archives before renewing their TUF envelopes.
pub(crate) fn prepare(fixture: &Path) -> PublishedGreeting {
    prepare_at(
        fixture,
        OffsetDateTime::now_utc().replace_nanosecond(0).unwrap(),
    )
}

/// Like [`prepare`], with online roles signed at `signed_at`. The test root stays valid
/// for two days from now, so a past `signed_at` replays metadata that has since expired.
pub(crate) fn prepare_at(fixture: &Path, signed_at: OffsetDateTime) -> PublishedGreeting {
    let accepted_at = OffsetDateTime::parse("2026-11-22T15:37:00Z", &Rfc3339).unwrap();
    let first = official_catalog(&fixture.join("v1.0.0"), accepted_at, None);
    let second = official_catalog(&fixture.join("v1.0.1"), accepted_at, Some(&first));

    let now = OffsetDateTime::now_utc().replace_nanosecond(0).unwrap();
    let mut repository = ReplayRepository::bootstrap(now + Duration::days(2), signed_at);
    let contracts = Contracts::new().unwrap();
    let target = if cfg!(target_arch = "x86_64") {
        "linux-amd64"
    } else {
        "linux-arm64"
    };

    let official = [first, second];
    let snapshots = std::array::from_fn(|index| {
        let (version, official_commit, catalog_revision) = RELEASES[index];
        let bytes = official[index].catalog_bytes();
        let document: Value = serde_json::from_slice(bytes).unwrap();
        assert_eq!(document["revision"].as_f64(), Some(catalog_revision as f64));
        let catalog = contracts.validate_catalog(&document).unwrap();
        let mut versions: Vec<_> = catalog
            .releases()
            .iter()
            .filter(|release| release["appId"] == ID)
            .map(|release| release["version"].as_str().unwrap())
            .collect();
        versions.sort_unstable();
        assert_eq!(versions, ["1.0.0", "1.0.1"][..=index]);

        let package = catalog
            .package(ID, version, target)
            .expect("Official native Greeting package");
        let asset = package.release_assets().archive;
        let archive_path = fixture.join(format!("{ID}-{version}-{target}.tar.zst"));
        assert_eq!(
            file_identity(&archive_path, asset.size_bytes).unwrap(),
            FileIdentity {
                sha256: asset.sha256.into(),
                size_bytes: asset.size_bytes
            },
            "{} differs from signed catalog {official_commit}",
            archive_path.display(),
        );

        let icons = catalog
            .releases()
            .iter()
            .filter_map(|release| {
                let icon = catalog
                    .icon_target(release["appId"].as_str()?, release["version"].as_str()?)?;
                let file = icon.path.strip_prefix("assets/").unwrap();
                let path =
                    fixture.join(format!("v{version}/targets/assets/{}.{file}", icon.sha256));
                Some((icon.path, read_file(&path, icon.size_bytes).unwrap()))
            })
            .collect();
        let files = repository
            .publish_with_icons(bytes, &icons, signed_at)
            .clone();

        PublishedSnapshot {
            version,
            official_commit,
            catalog_revision,
            catalog_sha256: digest(bytes),
            files,
            archive_path,
            archive_url: asset.url,
            archive_sha256: asset.sha256.into(),
            archive_size_bytes: asset.size_bytes,
            manifest_sha256: package.manifest_sha256().into(),
        }
    });
    PublishedGreeting {
        root: repository.root.clone(),
        snapshots,
        repository,
    }
}
