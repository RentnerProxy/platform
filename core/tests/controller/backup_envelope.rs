use std::{
    fs,
    io::Write,
    os::unix::fs::MetadataExt,
    path::Path,
    process::{Output, Stdio},
};

use aws_lc_rs::digest;
use rentnerproxy_artifacts::digest as artifact_digest;
use serde_json::Value;

use crate::common::isolated_command;

fn transfer(operation: &str, source: &Path, target: &Path, frame: &[u8]) -> Output {
    let mut child = isolated_command()
        .args(["--backup-envelope", operation])
        .arg(source)
        .arg(target)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(frame).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn native_envelope_cli_negotiates_its_format_and_publishes_only_complete_bytes() {
    let result = isolated_command()
        .args(["--backup-envelope", "version"])
        .output()
        .unwrap();
    assert!(result.status.success());
    assert_eq!(result.stdout, b"RPBAKENC/2\n");
    assert!(
        !isolated_command()
            .args(["--backup-envelope", "version", "extra"])
            .status()
            .unwrap()
            .success()
    );

    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    let restored = root.path().join("restored");
    fs::create_dir(&source).unwrap();
    fs::create_dir(&restored).unwrap();
    let filenames = [
        "metadata.json",
        "app-encryption-key",
        "postgres.dump",
        "controller-state.tar",
        "crowdsec-state.tar",
    ];
    let key = [33_u8; 32];
    let mut header = [0_u8; 96];
    header[..12].copy_from_slice(b"RPBAKENC\x02\x01\x00\x00");
    header[12..24].fill(41);
    header[24..56].copy_from_slice(digest::digest(&digest::SHA256, &key).as_ref());
    let mut hashes = Vec::new();
    for (index, name) in filenames.iter().enumerate() {
        let bytes = vec![index as u8; 19 + index];
        fs::write(source.join(name), &bytes).unwrap();
        header[56 + index * 8..64 + index * 8].copy_from_slice(&(bytes.len() as u64).to_be_bytes());
        hashes.extend_from_slice(digest::digest(&digest::SHA256, &bytes).as_ref());
    }
    let private = root.path().join("private");
    let published = root.path().join("published");
    let decryption = [key.as_slice(), header.as_slice()].concat();
    let encryption = [decryption.as_slice(), hashes.as_slice()].concat();
    let result = transfer("seal", &source, &private, &encryption);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let sealed = fs::read(&private).unwrap();
    let receipt: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(receipt["bytes"], sealed.len());
    assert_eq!(receipt["sha256"], artifact_digest(&sealed));
    fs::write(&published, b"preserve").unwrap();
    assert!(
        !transfer("publish", &private, &published, b"")
            .status
            .success()
    );
    assert_eq!(fs::read(&published).unwrap(), b"preserve");
    fs::remove_file(&published).unwrap();
    assert!(
        transfer("publish", &private, &published, b"")
            .status
            .success()
    );
    assert_eq!(fs::metadata(&published).unwrap().nlink(), 1);
    assert!(!private.exists());
    assert!(
        transfer("open", &published, &restored, &decryption)
            .status
            .success()
    );
    for name in filenames {
        assert_eq!(
            fs::read(restored.join(name)).unwrap(),
            fs::read(source.join(name)).unwrap()
        );
    }
}
