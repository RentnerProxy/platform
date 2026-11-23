use std::{
    ffi::CString,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    mem::MaybeUninit,
    os::{
        fd::AsRawFd,
        unix::{ffi::OsStrExt, fs::OpenOptionsExt},
    },
    path::Path,
    process::ExitCode,
};

use aead_gcm_stream::AesGcm;
use aes::Aes256;
use aws_lc_rs::{constant_time::verify_slices_are_equal, digest};
use zeroize::Zeroizing;

const NAMES: [&str; 5] = [
    "metadata.json",
    "app-encryption-key",
    "postgres.dump",
    "controller-state.tar",
    "crowdsec-state.tar",
];
const LARGE_ARTIFACT: u64 = 8 * 1024_u64.pow(3);
const LIMITS: [u64; NAMES.len()] = [
    512 * 1024,
    65_536,
    LARGE_ARTIFACT,
    LARGE_ARTIFACT,
    LARGE_ARTIFACT,
];
const HEADER_BYTES: usize = 96;
const TAG_BYTES: usize = 16;
const CHUNK_BYTES: usize = 65_536;
const RESERVE_BYTES: u128 = 2 * 1024_u128.pow(3);
const CHECK_INTERVAL: u64 = 16 * 1024 * 1024;
type CapacityCheck = fn(&File) -> io::Result<()>;

pub fn run_backup_envelope(mut arguments: impl Iterator<Item = String>) -> ExitCode {
    let Some(operation) = arguments.next() else {
        return ExitCode::FAILURE;
    };
    if operation == "version" {
        if arguments.next().is_some() {
            return ExitCode::FAILURE;
        }
        println!("RPBAKENC/1");
        return ExitCode::SUCCESS;
    }
    let (Some(source), Some(target), None) = (arguments.next(), arguments.next(), arguments.next())
    else {
        return ExitCode::FAILURE;
    };
    let (source, target) = (Path::new(&source), Path::new(&target));
    let result = if operation == "publish" {
        publish(source, target)
    } else {
        transform(
            &operation,
            source,
            target,
            io::stdin().lock(),
            io::stdout().lock(),
            check_capacity,
        )
    };
    if result.is_ok() {
        ExitCode::SUCCESS
    } else {
        eprintln!("Invalid or incomplete backup envelope transfer");
        ExitCode::FAILURE
    }
}

fn publish(source: &Path, target: &Path) -> io::Result<()> {
    let source = CString::new(source.as_os_str().as_bytes())?;
    let target = CString::new(target.as_os_str().as_bytes())?;
    // SAFETY: Both paths are valid, live NUL-terminated strings.
    if unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            target.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn transform(
    operation: &str,
    source: &Path,
    target: &Path,
    mut request: impl Read,
    mut response: impl Write,
    check: CapacityCheck,
) -> io::Result<()> {
    let mut key = Zeroizing::new([0; 32]);
    request.read_exact(key.as_mut())?;
    let mut header = [0; HEADER_BYTES];
    request.read_exact(&mut header)?;
    let lengths = verify_header(&header, &key)?;
    let mut cipher = AesGcm::<Aes256>::new((&*key).into(), &header[12..24]);
    cipher.set_aad(&header);
    match operation {
        "seal" => {
            let mut hashes = [[0; 32]; NAMES.len()];
            for sha256 in &mut hashes {
                request.read_exact(sha256)?;
            }
            eof(&mut request)?;
            let (length, hash) = seal(source, target, &header, lengths, hashes, cipher, check)?;
            serde_json::to_writer(
                &mut response,
                &serde_json::json!({"bytes": length, "sha256": hash}),
            )
            .map_err(io::Error::other)
        }
        "open" => {
            eof(&mut request)?;
            open(source, target, &header, lengths, cipher, check)
        }
        _ => Err(invalid()),
    }
}

fn verify_header(header: &[u8; HEADER_BYTES], key: &[u8; 32]) -> io::Result<[u64; NAMES.len()]> {
    if &header[..12] != b"RPBAKENC\x01\x01\x00\x00" {
        return Err(invalid());
    }
    verify_slices_are_equal(
        digest::digest(&digest::SHA256, key).as_ref(),
        &header[24..56],
    )
    .map_err(|_| invalid())?;
    let mut lengths = [0; NAMES.len()];
    let (fields, _) = header[56..].as_chunks::<8>();
    for (index, (field, limit)) in fields.iter().zip(LIMITS).enumerate() {
        let length = u64::from_be_bytes(*field);
        if !(1..=limit).contains(&length) {
            return Err(invalid());
        }
        lengths[index] = length;
    }
    Ok(lengths)
}

fn seal(
    source_directory: &Path,
    target: &Path,
    header: &[u8; HEADER_BYTES],
    lengths: [u64; NAMES.len()],
    hashes: [[u8; 32]; NAMES.len()],
    mut cipher: AesGcm<Aes256>,
    check: CapacityCheck,
) -> io::Result<(u64, String)> {
    let mut output = new_private_file(target)?;
    output.write_all(header)?;
    let mut checksum = digest::Context::new(&digest::SHA256);
    checksum.update(header);
    for ((name, expected_length), expected_hash) in NAMES.into_iter().zip(lengths).zip(hashes) {
        let path = source_directory.join(name);
        let (mut input, before) = marketplace_artifacts::open_regular(&path, expected_length)?;
        if before.len() != expected_length {
            return Err(invalid());
        }
        let mut artifact = digest::Context::new(&digest::SHA256);
        transfer(&mut input, &mut output, expected_length, check, |data| {
            artifact.update(data);
            cipher.encrypt(data);
            checksum.update(data);
        })?;
        eof(&mut input)?;
        if input.metadata()?.len() != before.len() || artifact.finish().as_ref() != expected_hash {
            return Err(invalid());
        }
    }
    let tag = cipher.finish();
    output.write_all(&tag)?;
    output.sync_all()?;
    checksum.update(&tag);
    let hash = checksum
        .finish()
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok((
        HEADER_BYTES as u64 + lengths.into_iter().sum::<u64>() + TAG_BYTES as u64,
        hash,
    ))
}

fn open(
    source: &Path,
    target_directory: &Path,
    expected_header: &[u8; HEADER_BYTES],
    lengths: [u64; NAMES.len()],
    mut cipher: AesGcm<Aes256>,
    check: CapacityCheck,
) -> io::Result<()> {
    let size = HEADER_BYTES as u64 + lengths.into_iter().sum::<u64>() + TAG_BYTES as u64;
    let (mut input, before) = marketplace_artifacts::open_regular(source, size)?;
    if before.len() != size {
        return Err(invalid());
    }
    let mut header = [0; HEADER_BYTES];
    input.read_exact(&mut header)?;
    if &header != expected_header {
        return Err(invalid());
    }
    for (name, length) in NAMES.into_iter().zip(lengths) {
        let mut output = new_private_file(&target_directory.join(name))?;
        transfer(&mut input, &mut output, length, check, |data| {
            cipher.decrypt(data)
        })?;
        output.sync_all()?;
    }
    let mut tag = [0; TAG_BYTES];
    input.read_exact(&mut tag)?;
    eof(&mut input)?;
    verify_slices_are_equal(cipher.finish().as_ref(), &tag).map_err(|_| invalid())
}

fn transfer(
    input: &mut File,
    output: &mut File,
    length: u64,
    check: CapacityCheck,
    mut transform: impl FnMut(&mut [u8]),
) -> io::Result<()> {
    let mut buffer = Zeroizing::new(vec![0; CHUNK_BYTES]);
    let mut offset = 0;
    while offset < length {
        if offset % CHECK_INTERVAL == 0 {
            check(output)?;
        }
        let bytes = ((length - offset).min(CHUNK_BYTES as u64)) as usize;
        let chunk = &mut buffer[..bytes];
        input.read_exact(chunk)?;
        transform(chunk);
        output.write_all(chunk)?;
        offset += bytes as u64;
    }
    Ok(())
}

fn new_private_file(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    Ok(file)
}

fn check_capacity(file: &File) -> io::Result<()> {
    let mut information = MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: The descriptor stays open, and statvfs initializes the pointed-to value on success.
    if unsafe { libc::fstatvfs(file.as_raw_fd(), information.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: The kernel has just initialized the structure successfully.
    let information = unsafe { information.assume_init() };
    let available = u128::from(information.f_bavail) * u128::from(information.f_bsize);
    if available < RESERVE_BYTES + u128::from(CHECK_INTERVAL) {
        return Err(io::Error::other("Backup space reserve unavailable"));
    }
    Ok(())
}

fn eof(input: &mut impl Read) -> io::Result<()> {
    if input.read(&mut [0])? == 0 {
        Ok(())
    } else {
        Err(invalid())
    }
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "Invalid backup envelope")
}

#[cfg(test)]
#[path = "../tests/private/backup_envelope.rs"]
mod tests;
