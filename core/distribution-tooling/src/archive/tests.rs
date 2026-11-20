use super::*;

const PATH: &str = "usr/bin/rentnerproxy";
const CONTENT: &[u8] = b"approved\n";

fn expected() -> [File; 1] {
    [File {
        path: PATH.into(),
        mode: 0o755,
        sha256: digest(CONTENT),
    }]
}

fn tar_checksum(header: &mut [u8]) {
    header[148..156].fill(b' ');
    let checksum: u32 = header[..512].iter().copied().map(u32::from).sum();
    header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
}

fn tar_entry(path: &str, mode: u32, owner: u32, kind: u8, link: &str) -> Vec<u8> {
    let mut header = [0; 512];
    header[..path.len()].copy_from_slice(path.as_bytes());
    header[100..108].copy_from_slice(format!("{mode:07o}\0").as_bytes());
    header[108..116].copy_from_slice(format!("{owner:07o}\0").as_bytes());
    header[116..124].copy_from_slice(b"0000000\0");
    header[124..136].copy_from_slice(format!("{:011o}\0", CONTENT.len()).as_bytes());
    header[136..148].copy_from_slice(b"00000000000\0");
    header[156] = kind;
    header[157..157 + link.len()].copy_from_slice(link.as_bytes());
    tar_checksum(&mut header);
    let mut bytes = header.to_vec();
    bytes.extend_from_slice(CONTENT);
    bytes.resize(2048, 0);
    bytes
}

fn cpio_entry(path: &str, content: &[u8], mode: u32, uid: u32, links: u32) -> Vec<u8> {
    let mut bytes = b"070701".to_vec();
    for field in [
        1,
        mode,
        uid,
        0,
        links,
        0,
        content.len() as u32,
        0,
        0,
        0,
        0,
        (path.len() + 1) as u32,
        0,
    ] {
        bytes.extend_from_slice(format!("{field:08x}").as_bytes());
    }
    bytes.extend_from_slice(path.as_bytes());
    bytes.push(0);
    bytes.resize(bytes.len().next_multiple_of(4), 0);
    bytes.extend_from_slice(content);
    bytes.resize(bytes.len().next_multiple_of(4), 0);
    bytes
}

fn cpio_archive(path: &str, mode: u32, uid: u32, links: u32) -> Vec<u8> {
    let mut bytes = cpio_entry(path, CONTENT, mode, uid, links);
    bytes.extend(cpio_entry("TRAILER!!!", b"", 0, 0, 1));
    bytes
}

#[test]
fn tar_authenticates_types_paths_modes_and_exact_inventory() {
    let valid = tar_entry(PATH, 0o755, 0, b'0', "");
    assert!(verify_tar(&valid, &expected()).is_ok());
    for path in ["../outside", "/absolute", "usr//bin", "usr/./bin"] {
        assert!(verify_tar(&tar_entry(path, 0o755, 0, b'0', ""), &expected()).is_err());
    }
    for change in [
        tar_entry("usr/bin/rentnerproxy/", 0o755, 0, b'0', ""),
        tar_entry(PATH, 0o4755, 0, b'0', ""),
        tar_entry(PATH, 0o755, 1, b'0', ""),
        tar_entry(PATH, 0o755, 0, b'0', "other"),
        tar_entry(PATH, 0o755, 0, b'x', ""),
        tar_entry(PATH, 0o755, 0, b'5', ""),
        [&valid[..1024], &valid].concat(),
        [&valid[..], b"trailing"].concat(),
        valid[..100].to_vec(),
    ] {
        assert!(verify_tar(&change, &expected()).is_err());
    }
    let mut invalid_header = valid;
    invalid_header[0] = b'x';
    assert!(verify_tar(&invalid_header, &expected()).is_err());
}

#[test]
fn tar_numbers_accept_only_octal_digits_and_field_padding() {
    for field in [&b"0000755\0"[..], b" 755\0 \0 ", b"755     ", b"00000755"] {
        assert_eq!(numeric(tar_digits(field).unwrap(), 8).unwrap(), 0o755);
    }
    for field in [
        &b"755\0x"[..],
        b"7 55",
        b"\t755",
        b"755\n",
        b"78",
        b"",
        b"\0 ",
    ] {
        assert!(tar_digits(field).is_err());
    }
    for (start, field) in [
        (100, &b"755\0x   "[..]),
        (108, b"0\0x     "),
        (116, b"0\0x     "),
        (124, b"11\0x        "),
        (136, b"00000000008\0"),
        (136, b"1\0x         "),
    ] {
        let mut tar = tar_entry(PATH, 0o755, 0, b'0', "");
        tar[start..start + field.len()].copy_from_slice(field);
        tar_checksum(&mut tar);
        assert!(verify_tar(&tar, &expected()).is_err());
    }
    let mut tar = tar_entry(PATH, 0o755, 0, b'0', "");
    tar[136..148].copy_from_slice(b"77777777777\0");
    tar_checksum(&mut tar);
    verify_tar(&tar, &expected()).unwrap();
    tar[155] = b'x';
    assert!(verify_tar(&tar, &expected()).is_err());
}

#[test]
fn tar_prefix_is_only_used_with_ustar_headers() {
    let mut prefixed = tar_entry("rentnerproxy", 0o755, 0, b'0', "");
    prefixed[345..352].copy_from_slice(b"usr/bin");
    tar_checksum(&mut prefixed);
    assert!(verify_tar(&prefixed, &expected()).is_err());
    prefixed[257..265].copy_from_slice(b"ustar\x0000");
    tar_checksum(&mut prefixed);
    assert!(verify_tar(&prefixed, &expected()).is_ok());
    let mut gnu = tar_entry(PATH, 0o755, 0, b'0', "");
    gnu[257..265].copy_from_slice(b"ustar  \0");
    tar_checksum(&mut gnu);
    assert!(verify_tar(&gnu, &expected()).is_ok());
}

#[test]
fn cpio_authenticates_types_paths_hard_links_and_terminator() {
    let valid = cpio_archive(PATH, 0o100755, 0, 1);
    assert!(verify_cpio(&valid, &expected()).is_ok());
    for path in ["../outside", "/absolute", "usr//bin", "usr/./bin"] {
        assert!(verify_cpio(&cpio_archive(path, 0o100755, 0, 1), &expected()).is_err());
    }
    for change in [
        cpio_archive(PATH, 0o100755, 1, 1),
        cpio_archive(PATH, 0o100755, 0, 2),
        cpio_archive(PATH, 0o100644, 0, 1),
        cpio_archive(PATH, 0o120755, 0, 1),
        cpio_archive(PATH, 0o060600, 0, 1),
        [&valid[..], b"trailing"].concat(),
        valid[..115].to_vec(),
        cpio_entry(PATH, CONTENT, 0o100755, 0, 1),
    ] {
        assert!(verify_cpio(&change, &expected()).is_err());
    }
    let mut invalid_field = valid.clone();
    invalid_field[23] = b'z';
    assert!(verify_cpio(&invalid_field, &expected()).is_err());
    let mut invalid_magic = valid;
    invalid_magic[5] = b'2';
    assert!(verify_cpio(&invalid_magic, &expected()).is_err());
}

#[test]
fn archives_reject_truncated_headers_missing_inventory_and_substitution() {
    for malformed in [
        Vec::new(),
        vec![0; 80],
        [b"070701", &[b'z'; 104][..]].concat(),
    ] {
        assert!(verify_tar(&malformed, &[]).is_err());
        assert!(verify_cpio(&malformed, &[]).is_err());
    }
    let empty_tar = [0; 1024];
    assert!(verify_tar(&empty_tar, &[]).is_ok());
    assert!(verify_tar(&empty_tar, &expected()).is_err());
    let mut tar = tar_entry(PATH, 0o755, 0, b'0', "");
    tar[512] = b'x';
    assert!(verify_tar(&tar, &expected()).is_err());

    let empty_cpio = cpio_entry("TRAILER!!!", b"", 0, 0, 1);
    assert!(verify_cpio(&empty_cpio, &[]).is_ok());
    assert!(verify_cpio(&empty_cpio, &expected()).is_err());
    let substituted = [cpio_entry(PATH, b"changed", 0o100755, 0, 1), empty_cpio].concat();
    assert!(verify_cpio(&substituted, &expected()).is_err());
}
