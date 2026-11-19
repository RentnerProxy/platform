use std::fs;

use aws_lc_rs::digest;

use super::{HEADER_BYTES, NAMES, transform};

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
