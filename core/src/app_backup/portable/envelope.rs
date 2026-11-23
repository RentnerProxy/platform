use super::{database, files, validate_data};
use crate::{
    app_backup::valid_portable_digest,
    app_install::recovery::{MAX_CHECKPOINT_BYTES, MAX_PACKAGE_BYTES},
    app_manager::portable_backup::Inventory,
};
use aws_lc_rs::digest::{Context, SHA256};
use marketplace_artifacts::{
    FileIdentity, StreamVerification, hash_stream, invalid, parse_json, verify_stream,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fmt::Write as _,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

const MAGIC: &[u8; 8] = b"RPAPPB2\0";
const PREFIX: u64 = 12;
const MAX_HEADER: usize = 8 * 1024 * 1024;
pub(super) const MAX_FILE_DATA: u64 = super::super::MAX_ARCHIVE as u64;
const MAX_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_MEMBERS: usize = 256 * 4 + 2;
const MAX_DATABASE_ALLOCATION: u64 = 9_007_199_254_740_991 / 2;

#[derive(Clone, Copy, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum Kind {
    Data,
    Checkpoint,
    Package,
    Database,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct Member {
    kind: Kind,
    key: String,
    bytes: u64,
    sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    allocation_bytes: Option<u64>,
}

impl Member {
    pub fn limit(kind: Kind) -> u64 {
        match kind {
            Kind::Data => MAX_FILE_DATA,
            Kind::Checkpoint => MAX_CHECKPOINT_BYTES,
            Kind::Package => MAX_PACKAGE_BYTES,
            Kind::Database => database::MAX_ARCHIVE,
        }
    }

    pub fn new(kind: Kind, key: String, identity: FileIdentity) -> Self {
        Self {
            kind,
            key,
            bytes: identity.size_bytes,
            sha256: identity.sha256,
            allocation_bytes: None,
        }
    }

    pub fn database(key: String, identity: FileIdentity, allocation_bytes: u64) -> Self {
        Self {
            allocation_bytes: Some(allocation_bytes),
            ..Self::new(Kind::Database, key, identity)
        }
    }

    fn identity(&self) -> FileIdentity {
        FileIdentity {
            size_bytes: self.bytes,
            sha256: self.sha256.clone(),
        }
    }

    fn destination(&self, directory: &Path) -> PathBuf {
        let prefix = match self.kind {
            Kind::Data => "data",
            Kind::Checkpoint => "checkpoint",
            Kind::Package => "package",
            Kind::Database => "database",
        };
        directory.join(format!("{prefix}-{}", self.key))
    }
}

pub(super) fn remaining_payload<'a>(
    members: impl IntoIterator<Item = &'a Member>,
) -> io::Result<u64> {
    members
        .into_iter()
        .try_fold(MAX_BYTES, |remaining, member| {
            remaining
                .checked_sub(member.bytes)
                .ok_or_else(|| invalid("Portable app backup exceeds its byte limit"))
        })
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Header {
    format_version: u8,
    installations: Inventory,
    members: Vec<Member>,
}

impl Header {
    fn validate(&self, header_bytes: usize) -> io::Result<u64> {
        self.installations.validate()?;
        if self.format_version != 2
            || self.installations.is_empty()
            || self.members.len() > MAX_MEMBERS
            || self
                .members
                .first()
                .is_none_or(|member| member.kind != Kind::Data)
        {
            return Err(invalid("Invalid portable app backup header"));
        }
        let packages = self.installations.package_digests();
        let databases = self.installations.databases();
        let mut expected_packages = packages.iter();
        let mut expected_databases = databases.iter();
        let mut previous = None;
        let mut checkpoint = false;
        let mut total = PREFIX + header_bytes as u64;
        for member in &self.members {
            let identity = (member.kind, member.key.as_str());
            if previous.is_some_and(|old| old >= identity)
                || member.bytes == 0
                || member.bytes > Member::limit(member.kind)
                || !valid_portable_digest(&member.sha256)
                || (member.kind == Kind::Database) != member.allocation_bytes.is_some()
                || member
                    .allocation_bytes
                    .is_some_and(|bytes| !(1..=MAX_DATABASE_ALLOCATION).contains(&bytes))
            {
                return Err(invalid("Invalid portable app backup member"));
            }
            total += member.bytes;
            if total > MAX_BYTES {
                return Err(invalid("Portable app backup exceeds its byte limit"));
            }
            previous = Some(identity);
            match member.kind {
                Kind::Data if member.key == "files" => {}
                Kind::Checkpoint if member.key == "catalog" => checkpoint = true,
                Kind::Package
                    if member.key == member.sha256
                        && expected_packages
                            .next()
                            .is_some_and(|digest| *digest == member.key) => {}
                Kind::Database
                    if expected_databases
                        .next()
                        .is_some_and(|uid| uid.to_string() == member.key) => {}
                _ => {
                    return Err(invalid(
                        "Portable app backup members differ from the inventory",
                    ));
                }
            }
        }
        if checkpoint == packages.is_empty()
            || expected_packages.next().is_some()
            || expected_databases.next().is_some()
        {
            return Err(invalid("Portable app backup does not cover the inventory"));
        }
        Ok(total)
    }
}

struct HashReader<R> {
    source: R,
    sha256: Context,
}

impl<R: Read> Read for HashReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.source.read(buffer)?;
        self.sha256.update(&buffer[..count]);
        Ok(count)
    }
}

pub(super) struct Backup {
    pub inventory: Inventory,
    pub data: BTreeMap<u32, Vec<files::Entry>>,
    pub checkpoint: Option<PathBuf>,
    pub packages: BTreeMap<String, PathBuf>,
    pub databases: BTreeMap<u32, PathBuf>,
    pub digest: String,
}

pub(super) fn read(path: &Path, directory: Option<&Path>) -> io::Result<Backup> {
    let file = open_file(path)?;
    let length = file.metadata()?.len();
    if !(PREFIX + 1..=MAX_BYTES).contains(&length) {
        return Err(invalid("Invalid portable app backup size"));
    }
    let mut source = HashReader {
        source: file,
        sha256: Context::new(&SHA256),
    };
    let mut magic = [0; MAGIC.len()];
    let mut size = [0; 4];
    source.read_exact(&mut magic)?;
    source.read_exact(&mut size)?;
    let header_bytes = u32::from_be_bytes(size) as usize;
    if &magic != MAGIC
        || !(1..=MAX_HEADER).contains(&header_bytes)
        || length - PREFIX < header_bytes as u64
    {
        return Err(invalid("Invalid portable app backup framing"));
    }
    let mut header = vec![0; header_bytes];
    source.read_exact(&mut header)?;
    let header: Header = serde_json::from_value(parse_json(&header)?)?;
    if header.validate(header_bytes)? != length {
        return Err(invalid(
            "Portable app backup length differs from the header",
        ));
    }

    let mut members = header.members.into_iter();
    let data_member = members
        .next()
        .ok_or_else(|| invalid("Missing application file data"))?;
    let mut data = Vec::with_capacity(data_member.bytes as usize);
    let mut data_source = (&mut source).take(data_member.bytes);
    if hash_stream(&mut data_source, &mut data, data_member.bytes)? != data_member.identity() {
        return Err(invalid("Application file data checksum mismatch"));
    }
    let data = decode_data(&data)?;
    validate_data(&header.installations, &data)?;

    let mut backup = Backup {
        inventory: header.installations,
        data,
        checkpoint: None,
        packages: BTreeMap::new(),
        databases: BTreeMap::new(),
        digest: String::new(),
    };
    for member in members {
        let target = directory.map(|dir| member.destination(dir));
        if verify_stream(
            (&mut source).take(member.bytes),
            &member.identity(),
            target.as_deref(),
        )? != StreamVerification::Verified
        {
            return Err(invalid("Portable app backup member checksum mismatch"));
        }
        if let Some(target) = target {
            match member.kind {
                Kind::Checkpoint => backup.checkpoint = Some(target),
                Kind::Package => {
                    backup.packages.insert(member.key, target);
                }
                Kind::Database => {
                    let uid = member
                        .key
                        .parse()
                        .map_err(|_| invalid("Invalid database member UID"))?;
                    backup.databases.insert(uid, target);
                }
                Kind::Data => return Err(invalid("Unexpected application file data")),
            }
        }
    }
    if source.read(&mut [0])? != 0 {
        return Err(invalid("Trailing bytes in portable app backup"));
    }
    let mut digest = String::with_capacity(64);
    for byte in source.sha256.finish().as_ref() {
        write!(&mut digest, "{byte:02x}").expect("writing into a String cannot fail");
    }
    backup.digest = digest;
    Ok(backup)
}

fn decode_data(bytes: &[u8]) -> io::Result<BTreeMap<u32, Vec<files::Entry>>> {
    let Value::Object(data) = parse_json(bytes)? else {
        return Err(invalid("Invalid portable application file data"));
    };
    data.into_iter()
        .map(|(key, entries)| {
            let uid = key
                .parse::<u32>()
                .map_err(|_| invalid("Invalid application file UID"))?;
            if uid.to_string() != key {
                return Err(invalid("Noncanonical application file UID"));
            }
            Ok((uid, serde_json::from_value(entries)?))
        })
        .collect()
}

pub(super) fn write(
    inventory: Inventory,
    members: Vec<(Member, PathBuf)>,
    mut output: impl Write,
) -> io::Result<()> {
    let (members, paths): (Vec<_>, Vec<_>) = members.into_iter().unzip();
    let header = Header {
        format_version: 2,
        installations: inventory,
        members,
    };
    let bytes = serde_json::to_vec(&header)?;
    if bytes.len() > MAX_HEADER {
        return Err(invalid("Portable app backup header exceeds its byte limit"));
    }
    header.validate(bytes.len())?;
    output.write_all(MAGIC)?;
    output.write_all(&(bytes.len() as u32).to_be_bytes())?;
    output.write_all(&bytes)?;
    for (member, path) in header.members.into_iter().zip(paths) {
        if hash_stream(open_file(&path)?, &mut output, member.bytes)? != member.identity() {
            return Err(invalid("Portable app backup member changed during capture"));
        }
    }
    output.flush()
}

fn open_file(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid("Portable app backup requires an ordinary file"));
    }
    Ok(file)
}

#[cfg(test)]
#[path = "../../../tests/private/app_backup/portable_envelope.rs"]
mod tests;
