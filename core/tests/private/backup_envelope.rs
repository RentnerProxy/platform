use std::{fs, io, path::Path};

use aws_lc_rs::{aead::Aad, digest, rand};
use serde_json::Value;

use super::{
    CHUNK_BYTES, HEADER_BYTES, NAMES, TAG_BYTES, chunk_nonce, payload_key, publish,
    run_backup_envelope, verify_header,
};

fn transform(
    mode: &str,
    source: &Path,
    target: &Path,
    request: &[u8],
    response: Vec<u8>,
) -> io::Result<()> {
    super::transform(mode, source, target, request, response, |_| Ok(()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

/// A known-answer vector produced by an independent implementation. The vectors are
/// data, read at run time, and never stand for a real key or salt.
fn vector(name: &str) -> Value {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/backup-envelope-vectors.json");
    let vectors: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    vectors[name].clone()
}

fn vector_bytes<const N: usize>(vector: &Value, field: &str) -> [u8; N] {
    unhex(vector[field].as_str().unwrap()).try_into().unwrap()
}

fn random<const N: usize>() -> [u8; N] {
    rand::generate(&rand::SystemRandom::new()).unwrap().expose()
}

/// A header for `format` and the frames that seal (with artifact hashes) and open it.
fn frames(
    format: u8,
    key: [u8; 32],
    salt: [u8; 12],
    entries: &[Vec<u8>],
) -> ([u8; HEADER_BYTES], Vec<u8>, Vec<u8>) {
    let mut header = [0; HEADER_BYTES];
    header[..12].copy_from_slice(&[
        b'R', b'P', b'B', b'A', b'K', b'E', b'N', b'C', format, 1, 0, 0,
    ]);
    header[12..24].copy_from_slice(&salt);
    header[24..56].copy_from_slice(digest::digest(&digest::SHA256, &key).as_ref());
    let mut hashes = Vec::new();
    for (index, bytes) in entries.iter().enumerate() {
        header[56 + index * 8..64 + index * 8].copy_from_slice(&(bytes.len() as u64).to_be_bytes());
        hashes.extend_from_slice(digest::digest(&digest::SHA256, bytes).as_ref());
    }
    let open = [key.as_slice(), header.as_slice()].concat();
    let seal = [open.as_slice(), hashes.as_slice()].concat();
    (header, seal, open)
}

fn write_entries(directory: &Path, entries: &[Vec<u8>]) {
    fs::create_dir_all(directory).unwrap();
    for (name, bytes) in NAMES.into_iter().zip(entries) {
        fs::write(directory.join(name), bytes).unwrap();
    }
}

fn assert_restored(directory: &Path, entries: &[Vec<u8>]) {
    for (name, bytes) in NAMES.into_iter().zip(entries) {
        assert_eq!(&fs::read(directory.join(name)).unwrap(), bytes);
    }
}

fn small_entries() -> Vec<Vec<u8>> {
    vec![
        b"a".to_vec(),
        b"xyz".to_vec(),
        vec![98; 17],
        vec![3; 61],
        b"last-one".to_vec(),
    ]
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
fn opens_existing_v1_stream_envelopes_but_never_seals_one() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    let restored = temp.path().join("restored");
    let entries = small_entries();
    write_entries(&source, &entries);
    fs::create_dir(&restored).unwrap();
    let stream = vector("v1Stream");
    let key = vector_bytes(&stream, "key");
    let (header, seal_frame, open_frame) = frames(1, key, vector_bytes(&stream, "salt"), &entries);
    // The OpenSSL AES-256-GCM stream of a v1 envelope from earlier releases.
    let payload = unhex(stream["payload"].as_str().unwrap());
    let envelope = temp.path().join("v1.rpba");
    fs::write(&envelope, [header.as_slice(), &payload].concat()).unwrap();
    assert!(
        transform(
            "seal",
            &source,
            &temp.path().join("new.rpba"),
            &seal_frame,
            Vec::new()
        )
        .is_err()
    );
    assert!(!temp.path().join("new.rpba").exists());
    transform("open", &envelope, &restored, &open_frame, Vec::new()).unwrap();
    assert_restored(&restored, &entries);

    let corrupt = temp.path().join("corrupt");
    fs::create_dir(&corrupt).unwrap();
    let mut tampered = [header.as_slice(), &payload].concat();
    *tampered.last_mut().unwrap() ^= 1;
    fs::write(&envelope, tampered).unwrap();
    assert!(transform("open", &envelope, &corrupt, &open_frame, Vec::new()).is_err());
}

#[test]
fn seals_chunked_envelopes_that_match_an_independent_implementation() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    let restored = temp.path().join("restored");
    let entries = small_entries();
    write_entries(&source, &entries);
    fs::create_dir(&restored).unwrap();
    let small = vector("small");
    let (header, seal_frame, open_frame) = frames(
        2,
        vector_bytes(&small, "key"),
        vector_bytes(&small, "salt"),
        &entries,
    );
    let encrypted = temp.path().join("backup.rpba");
    let mut receipt = Vec::new();
    super::transform(
        "seal",
        &source,
        &encrypted,
        seal_frame.as_slice(),
        &mut receipt,
        |_| Ok(()),
    )
    .unwrap();
    let ciphertext = fs::read(&encrypted).unwrap();
    assert_eq!(&ciphertext[..HEADER_BYTES], header.as_slice());
    // Produced by Node's AES-256-GCM and HKDF from the same key, header and artifacts.
    assert_eq!(
        hex(&ciphertext[HEADER_BYTES..]),
        small["payload"].as_str().unwrap()
    );
    let receipt: serde_json::Value = serde_json::from_slice(&receipt).unwrap();
    assert_eq!(receipt["bytes"], ciphertext.len());
    assert_eq!(
        receipt["sha256"],
        hex(digest::digest(&digest::SHA256, &ciphertext).as_ref())
    );
    transform("open", &encrypted, &restored, &open_frame, Vec::new()).unwrap();
    assert_restored(&restored, &entries);

    // The same check for artifacts that cross chunk boundaries inside and between them.
    let sizes = [1, 3, 70_000, 65_536, 9];
    let large: Vec<Vec<u8>> = sizes
        .iter()
        .enumerate()
        .map(|(index, size)| {
            (0..*size)
                .map(|offset| ((offset * 7 + index * 13) % 251) as u8)
                .collect()
        })
        .collect();
    let large_source = temp.path().join("large");
    write_entries(&large_source, &large);
    let large_vector = vector("large");
    let large_key = vector_bytes(&large_vector, "key");
    let (_, large_seal, large_open) =
        frames(2, large_key, vector_bytes(&large_vector, "salt"), &large);
    let large_encrypted = temp.path().join("large.rpba");
    transform(
        "seal",
        &large_source,
        &large_encrypted,
        &large_seal,
        Vec::new(),
    )
    .unwrap();
    let sealed = fs::read(&large_encrypted).unwrap();
    assert_eq!(sealed.len(), 135_693);
    // SHA-256 of the same envelope sealed by Node's AES-256-GCM and HKDF.
    assert_eq!(
        hex(digest::digest(&digest::SHA256, &sealed).as_ref()),
        large_vector["sha256"].as_str().unwrap()
    );
    let large_restored = temp.path().join("large-restored");
    fs::create_dir(&large_restored).unwrap();
    transform(
        "open",
        &large_encrypted,
        &large_restored,
        &large_open,
        Vec::new(),
    )
    .unwrap();
    assert_restored(&large_restored, &large);

    // An artifact that ends exactly on a chunk boundary, in a payload that is an exact
    // multiple of 64 KiB: two full chunks, the second one final, and no empty third chunk.
    let aligned: Vec<Vec<u8>> = [1, 3, 65_532, 65_535, 1]
        .iter()
        .enumerate()
        .map(|(index, size)| {
            (0..*size)
                .map(|offset| ((offset * 11 + index * 17) % 253) as u8)
                .collect()
        })
        .collect();
    let aligned_source = temp.path().join("aligned");
    write_entries(&aligned_source, &aligned);
    let aligned_vector = vector("aligned");
    let (_, aligned_seal, aligned_open) = frames(
        2,
        vector_bytes(&aligned_vector, "key"),
        vector_bytes(&aligned_vector, "salt"),
        &aligned,
    );
    let aligned_encrypted = temp.path().join("aligned.rpba");
    transform(
        "seal",
        &aligned_source,
        &aligned_encrypted,
        &aligned_seal,
        Vec::new(),
    )
    .unwrap();
    let aligned_sealed = fs::read(&aligned_encrypted).unwrap();
    assert_eq!(
        aligned_sealed.len(),
        HEADER_BYTES + 2 * (CHUNK_BYTES + TAG_BYTES)
    );
    // Node's OpenSSL and Bun's BoringSSL both produce this envelope.
    assert_eq!(
        hex(digest::digest(&digest::SHA256, &aligned_sealed).as_ref()),
        aligned_vector["sha256"].as_str().unwrap()
    );
    let aligned_restored = temp.path().join("aligned-restored");
    fs::create_dir(&aligned_restored).unwrap();
    transform(
        "open",
        &aligned_encrypted,
        &aligned_restored,
        &aligned_open,
        Vec::new(),
    )
    .unwrap();
    assert_restored(&aligned_restored, &aligned);

    // Altered, reordered or resealed chunks never authenticate.
    let sealed_chunk = CHUNK_BYTES + TAG_BYTES;
    let mut swapped = sealed.clone();
    let (first, rest) = swapped[HEADER_BYTES..].split_at_mut(sealed_chunk);
    first.swap_with_slice(&mut rest[..sealed_chunk]);
    let mut flipped = sealed.clone();
    flipped[HEADER_BYTES + sealed_chunk + 5] ^= 1;
    let mut tag = sealed.clone();
    *tag.last_mut().unwrap() ^= 1;
    // A final chunk sealed as if more followed would let a shorter stream look complete.
    let mut unterminated = sealed[..HEADER_BYTES + 2 * sealed_chunk].to_vec();
    let mut payload = Vec::new();
    for entry in &large {
        payload.extend_from_slice(entry);
    }
    let mut last = payload[2 * CHUNK_BYTES..].to_vec();
    let header: [u8; HEADER_BYTES] = sealed[..HEADER_BYTES].try_into().unwrap();
    let seal_tag = payload_key(&large_key, &header)
        .unwrap()
        .seal_in_place_separate_tag(chunk_nonce(2, false), Aad::from(header), &mut last)
        .unwrap();
    unterminated.extend_from_slice(&last);
    unterminated.extend_from_slice(seal_tag.as_ref());
    for (case, bytes) in [
        ("swapped", swapped),
        ("flipped", flipped),
        ("tag", tag),
        ("unterminated", unterminated),
        ("short", sealed[..sealed.len() - 1].to_vec()),
        ("trailing", [sealed.as_slice(), b"x"].concat()),
    ] {
        let file = temp.path().join(format!("{case}.rpba"));
        fs::write(&file, bytes).unwrap();
        let target = temp.path().join(case);
        fs::create_dir(&target).unwrap();
        assert!(
            transform("open", &file, &target, &large_open, Vec::new()).is_err(),
            "{case}"
        );
        // The first, intact chunk may be staged; a later failure still rejects the envelope.
        assert!(
            !target.join(NAMES[4]).exists(),
            "{case} published the last artifact"
        );
    }
}

#[test]
fn checks_headers_frames_and_sources_before_sealing() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    let restored = temp.path().join("restored");
    let entries = small_entries();
    write_entries(&source, &entries);
    fs::create_dir(&restored).unwrap();
    let key = random::<32>();
    let (header, seal_frame, open_frame) = frames(2, key, random(), &entries);
    let encrypted = temp.path().join("backup.rpba");

    assert_eq!(
        run_backup_envelope(std::iter::empty()),
        std::process::ExitCode::FAILURE
    );
    assert_eq!(verify_header(&header, &key).unwrap().0, 2);
    for offset in [0, 8, 9, 11, 24, 63] {
        let mut invalid = header;
        invalid[offset] ^= 1;
        assert!(verify_header(&invalid, &key).is_err(), "{offset}");
    }
    let mut unknown = header;
    unknown[8] = 3;
    assert!(verify_header(&unknown, &key).is_err());
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

    transform("seal", &source, &encrypted, &seal_frame, Vec::new()).unwrap();
    let ciphertext = fs::read(&encrypted).unwrap();
    // Never overwrites an existing envelope.
    assert!(transform("seal", &source, &encrypted, &seal_frame, Vec::new()).is_err());
    assert_eq!(fs::read(&encrypted).unwrap(), ciphertext);
    // A changed or grown artifact no longer matches its announced hash or length.
    fs::write(source.join(NAMES[0]), b"b").unwrap();
    assert!(
        transform(
            "seal",
            &source,
            &temp.path().join("changed.rpba"),
            &seal_frame,
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
            &seal_frame,
            Vec::new()
        )
        .is_err()
    );
    let mut changed_header = open_frame.clone();
    changed_header[44] ^= 1;
    assert!(transform("open", &encrypted, &restored, &changed_header, Vec::new()).is_err());
    assert_eq!(fs::read_dir(&restored).unwrap().count(), 0);
}
