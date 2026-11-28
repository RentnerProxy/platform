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
use aws_lc_rs::{
    aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey},
    constant_time::verify_slices_are_equal,
    digest, hkdf,
};
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
/// The most one capacity check admits: a full interval of v2 chunks with their tags.
const CHECK_BYTES: u128 =
    CHECK_INTERVAL as u128 + (CHECK_INTERVAL as u128 / CHUNK_BYTES as u128) * TAG_BYTES as u128;
/// v1 encrypts all artifacts as one AES-256-GCM stream. It is only opened.
const STREAM_FORMAT: u8 = 1;
/// v2 seals each 64 KiB chunk of the artifacts on its own with AES-256-GCM.
const CHUNKED_FORMAT: u8 = 2;
const PAYLOAD_KEY_INFO: &[u8] = b"RPBAKENC/2 AES-256-GCM payload key";
type CapacityCheck = fn(&File) -> io::Result<()>;

pub fn run_backup_envelope(mut arguments: impl Iterator<Item = String>) -> ExitCode {
    let Some(operation) = arguments.next() else {
        return ExitCode::FAILURE;
    };
    if operation == "version" {
        if arguments.next().is_some() {
            return ExitCode::FAILURE;
        }
        // Sealing writes v2. Opening also accepts v1 envelopes.
        println!("RPBAKENC/2");
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
    let (format, lengths) = verify_header(&header, &key)?;
    match (operation, format) {
        // New envelopes are always chunked.
        ("seal", CHUNKED_FORMAT) => {
            let mut hashes = [[0; 32]; NAMES.len()];
            for sha256 in &mut hashes {
                request.read_exact(sha256)?;
            }
            eof(&mut request)?;
            let payload = payload_key(&key, &header)?;
            let (length, hash) = seal(source, target, &header, lengths, hashes, &payload, check)?;
            serde_json::to_writer(
                &mut response,
                &serde_json::json!({"bytes": length, "sha256": hash}),
            )
            .map_err(io::Error::other)
        }
        ("open", CHUNKED_FORMAT) => {
            eof(&mut request)?;
            let payload = payload_key(&key, &header)?;
            open(source, target, &header, lengths, &payload, check)
        }
        ("open", STREAM_FORMAT) => {
            eof(&mut request)?;
            let mut cipher = AesGcm::<Aes256>::new((&*key).into(), &header[12..24]);
            cipher.set_aad(&header);
            open_stream(source, target, &header, lengths, cipher, check)
        }
        _ => Err(invalid()),
    }
}

fn verify_header(
    header: &[u8; HEADER_BYTES],
    key: &[u8; 32],
) -> io::Result<(u8, [u64; NAMES.len()])> {
    let format = header[8];
    if &header[..8] != b"RPBAKENC"
        || !matches!(format, STREAM_FORMAT | CHUNKED_FORMAT)
        || header[9..12] != [1, 0, 0]
    {
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
    Ok((format, lengths))
}

/// Derive the envelope's own AES-256-GCM key from the recovery key and the header's
/// random salt. Chunk nonces are counters, so they never repeat under one payload key.
fn payload_key(key: &[u8; 32], header: &[u8; HEADER_BYTES]) -> io::Result<LessSafeKey> {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &header[12..24]).extract(key);
    let okm = prk
        .expand(&[PAYLOAD_KEY_INFO], &AES_256_GCM)
        .map_err(|_| invalid())?;
    Ok(LessSafeKey::new(UnboundKey::from(okm)))
}

/// Chunk `index` uses a 64-bit big-endian counter, and its last byte marks the final
/// chunk, so reordered, dropped or truncated chunks never authenticate.
fn chunk_nonce(index: u64, last: bool) -> Nonce {
    let mut nonce = [0; NONCE_LEN];
    nonce[3..11].copy_from_slice(&index.to_be_bytes());
    nonce[11] = u8::from(last);
    Nonce::assume_unique_for_key(nonce)
}

fn chunks(payload: u64) -> u64 {
    payload.div_ceil(CHUNK_BYTES as u64)
}

fn sealed_bytes(lengths: [u64; NAMES.len()]) -> u64 {
    let payload = lengths.into_iter().sum::<u64>();
    HEADER_BYTES as u64 + payload + chunks(payload) * TAG_BYTES as u64
}

fn seal(
    source_directory: &Path,
    target: &Path,
    header: &[u8; HEADER_BYTES],
    lengths: [u64; NAMES.len()],
    hashes: [[u8; 32]; NAMES.len()],
    key: &LessSafeKey,
    check: CapacityCheck,
) -> io::Result<(u64, String)> {
    let mut output = new_private_file(target)?;
    output.write_all(header)?;
    let mut checksum = digest::Context::new(&digest::SHA256);
    checksum.update(header);
    let mut chunk = Chunks::new(lengths);
    for ((name, expected_length), expected_hash) in NAMES.into_iter().zip(lengths).zip(hashes) {
        let path = source_directory.join(name);
        let (mut input, before) = rentnerproxy_artifacts::open_regular(&path, expected_length)?;
        if before.len() != expected_length {
            return Err(invalid());
        }
        let mut artifact = digest::Context::new(&digest::SHA256);
        let mut remaining = expected_length;
        while remaining > 0 {
            let space = chunk.space().min(remaining);
            let data = chunk.fill(space);
            input.read_exact(data)?;
            artifact.update(data);
            remaining -= space;
            let last = chunk.done();
            if let Some((sealed, index)) = chunk.full() {
                if (index * CHUNK_BYTES as u64).is_multiple_of(CHECK_INTERVAL) {
                    check(&output)?;
                }
                let tag = key
                    .seal_in_place_separate_tag(chunk_nonce(index, last), Aad::from(header), sealed)
                    .map_err(|_| invalid())?;
                output.write_all(sealed)?;
                output.write_all(tag.as_ref())?;
                checksum.update(sealed);
                checksum.update(tag.as_ref());
                chunk.next();
            }
        }
        eof(&mut input)?;
        if input.metadata()?.len() != before.len() || artifact.finish().as_ref() != expected_hash {
            return Err(invalid());
        }
    }
    output.sync_all()?;
    let hash = checksum
        .finish()
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok((sealed_bytes(lengths), hash))
}

fn open(
    source: &Path,
    target_directory: &Path,
    expected_header: &[u8; HEADER_BYTES],
    lengths: [u64; NAMES.len()],
    key: &LessSafeKey,
    check: CapacityCheck,
) -> io::Result<()> {
    let size = sealed_bytes(lengths);
    let (mut input, before) = rentnerproxy_artifacts::open_regular(source, size)?;
    if before.len() != size {
        return Err(invalid());
    }
    let mut header = [0; HEADER_BYTES];
    input.read_exact(&mut header)?;
    if &header != expected_header {
        return Err(invalid());
    }
    let payload = lengths.into_iter().sum::<u64>();
    let count = chunks(payload);
    let directory = File::open(target_directory)?;
    let mut buffer = Zeroizing::new(vec![0; CHUNK_BYTES + TAG_BYTES]);
    let mut artifacts = NAMES.into_iter().zip(lengths);
    let mut current: Option<(File, u64)> = None;
    for index in 0..count {
        if (index * CHUNK_BYTES as u64).is_multiple_of(CHECK_INTERVAL) {
            check(&directory)?;
        }
        let plain = (payload - index * CHUNK_BYTES as u64).min(CHUNK_BYTES as u64) as usize;
        let sealed = &mut buffer[..plain + TAG_BYTES];
        input.read_exact(sealed)?;
        // Plaintext reaches the staging files only after its chunk authenticated.
        let mut data = &*key
            .open_in_place(
                chunk_nonce(index, index + 1 == count),
                Aad::from(header),
                sealed,
            )
            .map_err(|_| invalid())?;
        while !data.is_empty() {
            if current.is_none() {
                let (name, length) = artifacts.next().ok_or_else(invalid)?;
                current = Some((new_private_file(&target_directory.join(name))?, length));
            }
            let Some((output, remaining)) = current.as_mut() else {
                return Err(invalid());
            };
            let part = data
                .len()
                .min(usize::try_from(*remaining).unwrap_or(usize::MAX));
            output.write_all(&data[..part])?;
            *remaining -= part as u64;
            data = &data[part..];
            if *remaining == 0 {
                output.sync_all()?;
                current = None;
            }
        }
    }
    if current.is_some() || artifacts.next().is_some() {
        return Err(invalid());
    }
    eof(&mut input)
}

/// The chunk being filled from consecutive artifacts while sealing.
struct Chunks {
    buffer: Zeroizing<Vec<u8>>,
    filled: usize,
    index: u64,
    remaining: u64,
}

impl Chunks {
    fn new(lengths: [u64; NAMES.len()]) -> Self {
        Self {
            buffer: Zeroizing::new(vec![0; CHUNK_BYTES]),
            filled: 0,
            index: 0,
            remaining: lengths.into_iter().sum(),
        }
    }

    fn space(&self) -> u64 {
        (CHUNK_BYTES - self.filled) as u64
    }

    fn fill(&mut self, bytes: u64) -> &mut [u8] {
        let start = self.filled;
        self.filled += bytes as usize;
        self.remaining -= bytes;
        &mut self.buffer[start..self.filled]
    }

    /// A chunk is complete when it is full or holds the payload's last byte.
    fn full(&mut self) -> Option<(&mut [u8], u64)> {
        (self.filled == CHUNK_BYTES || self.remaining == 0)
            .then(|| (&mut self.buffer[..self.filled], self.index))
    }

    fn done(&self) -> bool {
        self.remaining == 0
    }

    fn next(&mut self) {
        self.filled = 0;
        self.index += 1;
    }
}

fn open_stream(
    source: &Path,
    target_directory: &Path,
    expected_header: &[u8; HEADER_BYTES],
    lengths: [u64; NAMES.len()],
    mut cipher: AesGcm<Aes256>,
    check: CapacityCheck,
) -> io::Result<()> {
    let size = HEADER_BYTES as u64 + lengths.into_iter().sum::<u64>() + TAG_BYTES as u64;
    let (mut input, before) = rentnerproxy_artifacts::open_regular(source, size)?;
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
    if available < RESERVE_BYTES + CHECK_BYTES {
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
