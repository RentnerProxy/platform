use std::{fs, io, path::Path};

use aws_lc_rs::digest;

use super::{HEADER_BYTES, NAMES, publish, run_backup_envelope, verify_header};

fn transform(
    mode: &str,
    source: &Path,
    target: &Path,
    request: &[u8],
    response: Vec<u8>,
) -> io::Result<()> {
    super::transform(mode, source, target, request, response, |_| Ok(()))
}

#[test]
fn atomically_publishes_a_single_file_without_replacing_existing_output() {
    use std::os::unix::fs::MetadataExt;

    let temp = tempfile::tempdir().unwrap();
    let private = temp.path().join("private");
    fs::create_dir(&private).unwrap();
    let source = private.join("sealed");
    let output = temp.path().join("backup");
    fs::write(&source, b"sealed").unwrap();
    fs::write(&output, b"unrelated").unwrap();
    assert_eq!(
        publish(&source, &output).unwrap_err().kind(),
        io::ErrorKind::AlreadyExists
    );
    assert_eq!(fs::read(&output).unwrap(), b"unrelated");
    fs::remove_file(&output).unwrap();
    publish(&source, &output).unwrap();
    assert_eq!(fs::read(&output).unwrap(), b"sealed");
    assert_eq!(fs::metadata(&output).unwrap().nlink(), 1);
    assert!(!source.exists());
}

#[test]
fn matches_the_openssl_v1_envelope_across_artifact_boundaries() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    let restored = temp.path().join("restored");
    fs::create_dir(&source).unwrap();
    fs::create_dir(&restored).unwrap();

    let key = [37; 32];
    let entries: [&[u8]; 5] = [b"a", b"xyz", &[98; 17], &[3; 61], b"last-one"];
    let mut header = [0; HEADER_BYTES];
    header[..12].copy_from_slice(b"RPBAKENC\x01\x01\x00\x00");
    header[12..24].fill(29);
    header[24..56].copy_from_slice(digest::digest(&digest::SHA256, &key).as_ref());
    let mut hashes = Vec::new();
    for (index, (name, bytes)) in NAMES.into_iter().zip(entries).enumerate() {
        fs::write(source.join(name), bytes).unwrap();
        header[56 + index * 8..64 + index * 8].copy_from_slice(&(bytes.len() as u64).to_be_bytes());
        hashes.extend_from_slice(digest::digest(&digest::SHA256, bytes).as_ref());
    }

    let encrypted = temp.path().join("backup.rpba");
    let open_frame = [key.as_slice(), header.as_slice()].concat();
    let seal_frame = [open_frame.as_slice(), hashes.as_slice()].concat();
    transform(
        "seal",
        &source,
        &encrypted,
        seal_frame.as_slice(),
        Vec::new(),
    )
    .unwrap();
    let ciphertext = fs::read(&encrypted).unwrap();
    let hex: String = ciphertext[HEADER_BYTES..]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        hex,
        "d2bbebb10e3dbf3e53b3a79ec707c750da88c3c687b007d3f81dad18d195e6aa22075d835ef22eaad63c91bd81ce0c8c29c6f12e3462f64cd61e8fd25463831e1cbd43ba61f0c12715dd297def648253d7136bfb2382508f973d1f5586e4277b1890ae0684789ec14ca2",
    );

    assert_eq!(
        run_backup_envelope(std::iter::empty()),
        std::process::ExitCode::FAILURE
    );
    for offset in [0, 11, 24, 63] {
        let mut invalid = header;
        invalid[offset] ^= 1;
        assert!(verify_header(&invalid, &key).is_err());
    }
    assert!(verify_header(&header, &[0; 32]).is_err());
    let mut maximum_metadata = header;
    maximum_metadata[56..64].copy_from_slice(&(512_u64 * 1024).to_be_bytes());
    assert!(verify_header(&maximum_metadata, &key).is_ok());
    maximum_metadata[56..64].copy_from_slice(&(512_u64 * 1024 + 1).to_be_bytes());
    assert!(verify_header(&maximum_metadata, &key).is_err());
    for (mode, request) in [
        ("seal", &seal_frame[..seal_frame.len() - 1]),
        ("open", &open_frame[..8]),
        ("open", &open_frame[..40]),
        ("unknown", open_frame.as_slice()),
    ] {
        assert!(transform(mode, &source, &restored, request, Vec::new()).is_err());
    }
    let trailing = [open_frame.as_slice(), b"x"].concat();
    assert!(transform("open", &source, &restored, trailing.as_slice(), Vec::new()).is_err());
    assert!(
        transform(
            "seal",
            &source,
            &encrypted,
            seal_frame.as_slice(),
            Vec::new()
        )
        .is_err()
    );
    assert_eq!(fs::read(&encrypted).unwrap(), ciphertext);

    let changed_archive = temp.path().join("changed.rpba");
    fs::write(source.join(NAMES[0]), b"b").unwrap();
    assert!(
        transform(
            "seal",
            &source,
            &changed_archive,
            seal_frame.as_slice(),
            Vec::new()
        )
        .is_err()
    );
    fs::write(source.join(NAMES[0]), b"longer").unwrap();
    assert!(
        transform(
            "seal",
            &source,
            &temp.path().join("oversize.rpba"),
            seal_frame.as_slice(),
            Vec::new()
        )
        .is_err()
    );
    fs::write(source.join(NAMES[0]), entries[0]).unwrap();

    let short = temp.path().join("short.rpba");
    fs::write(&short, &ciphertext[..ciphertext.len() - 1]).unwrap();
    assert!(transform("open", &short, &restored, open_frame.as_slice(), Vec::new()).is_err());
    let mut changed_header = open_frame.clone();
    changed_header[44] ^= 1;
    assert!(
        transform(
            "open",
            &encrypted,
            &restored,
            changed_header.as_slice(),
            Vec::new()
        )
        .is_err()
    );
    assert_eq!(fs::read_dir(&restored).unwrap().count(), 0);

    transform(
        "open",
        &encrypted,
        &restored,
        open_frame.as_slice(),
        Vec::new(),
    )
    .unwrap();
    for (name, bytes) in NAMES.into_iter().zip(entries) {
        assert_eq!(fs::read(restored.join(name)).unwrap(), bytes);
    }
    let corrupt = temp.path().join("corrupt");
    fs::create_dir(&corrupt).unwrap();
    let mut ciphertext = ciphertext;
    *ciphertext.last_mut().unwrap() ^= 1;
    fs::write(&encrypted, ciphertext).unwrap();
    assert!(
        transform(
            "open",
            &encrypted,
            &corrupt,
            open_frame.as_slice(),
            Vec::new()
        )
        .is_err()
    );
}
