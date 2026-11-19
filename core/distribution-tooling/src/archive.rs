use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read, Write};

use base64::{Engine, engine::general_purpose::STANDARD};
use flate2::read::MultiGzDecoder;
use marketplace_artifacts::{digest, invalid};
use serde::Deserialize;

use crate::{BUNDLE_BYTES, read_bounded};

#[cfg(test)]
mod tests;

pub const ARCHIVE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct File {
    pub path: String,
    pub mode: u32,
    pub sha256: String,
}

struct Entry<'a> {
    mode: u32,
    data: &'a [u8],
    directory: bool,
}

type Inventory<'a> = BTreeMap<String, Entry<'a>>;

fn path_name(value: &str) -> io::Result<&str> {
    let path = value.strip_prefix("./").unwrap_or(value);
    let path = path.strip_suffix('/').unwrap_or(path);
    if path.is_empty() || path == "." {
        return Ok("");
    }
    if !path.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'+' | b'/' | b'-')
    }) || path.split('/').any(|part| matches!(part, "" | "." | ".."))
    {
        return Err(invalid("Unsafe package archive path"));
    }
    Ok(path)
}

fn value(bytes: &[u8]) -> io::Result<&str> {
    std::str::from_utf8(bytes).map_err(|_| invalid("Invalid package archive text"))
}

fn numeric(bytes: &[u8], radix: u32) -> io::Result<u32> {
    if bytes.is_empty() || !bytes.iter().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid("Invalid package archive numeric field"));
    }
    u32::from_str_radix(value(bytes)?, radix)
        .map_err(|_| invalid("Invalid package archive numeric field"))
}

fn add_entry<'a>(
    files: &mut Inventory<'a>,
    path: &str,
    mode: u32,
    data: &'a [u8],
    directory: bool,
) -> io::Result<()> {
    if (!directory && path.is_empty())
        || files.len() >= 4096
        || files
            .insert(
                path.to_owned(),
                Entry {
                    mode,
                    data,
                    directory,
                },
            )
            .is_some()
    {
        return Err(invalid("Unexpected package files"));
    }
    Ok(())
}

fn tar(mut bytes: &[u8]) -> io::Result<Inventory<'_>> {
    let mut files = BTreeMap::new();
    while let Some(header) = bytes.get(..512) {
        if header.iter().all(|byte| *byte == 0) {
            if bytes.iter().any(|byte| *byte != 0) {
                return Err(invalid("Trailing package tar data"));
            }
            return Ok(files);
        }
        let text = |start, end| -> io::Result<&str> {
            let field: &[u8] = &header[start..end];
            value(field.split(|byte| *byte == 0).next().unwrap_or_default())
        };
        let octal = |start, end| numeric(text(start, end)?.trim().as_bytes(), 8);
        let checksum: u32 = header
            .iter()
            .enumerate()
            .map(|(index, byte)| {
                u32::from(if (148..156).contains(&index) {
                    32
                } else {
                    *byte
                })
            })
            .sum();
        if checksum != octal(148, 156)?
            || octal(108, 116)? != 0
            || octal(116, 124)? != 0
            || !text(157, 257)?.is_empty()
            || !matches!(text(265, 297)?, "" | "root")
            || !matches!(text(297, 329)?, "" | "root")
        {
            return Err(invalid("Invalid package tar ownership or links"));
        }
        let name = text(0, 100)?;
        let prefix = text(345, 500)?;
        let combined;
        let path = if prefix.is_empty() {
            path_name(name)?
        } else {
            combined = format!("{prefix}/{name}");
            path_name(&combined)?
        };
        let size = octal(124, 136)? as usize;
        if size as u64 > ARCHIVE_BYTES {
            return Err(invalid("Unsupported package tar entry size"));
        }
        let mode = octal(100, 108)?;
        let directory = match header[156] {
            0 | b'0' => false,
            b'5' if size == 0 && mode <= 0o777 => true,
            _ => return Err(invalid("Unsupported package tar entry")),
        };
        let data = bytes
            .get(512..512 + size)
            .ok_or_else(|| invalid("Truncated package tar entry"))?;
        add_entry(&mut files, path, mode, data, directory)?;
        bytes = bytes
            .get(512 + size.next_multiple_of(512)..)
            .ok_or_else(|| invalid("Truncated package tar padding"))?;
    }
    Err(invalid("Missing package tar terminator"))
}

fn cpio(mut bytes: &[u8]) -> io::Result<Inventory<'_>> {
    let mut files = BTreeMap::new();
    while let Some(header) = bytes.get(..110) {
        if &header[..6] != b"070701" {
            return Err(invalid("Unsupported package cpio"));
        }
        let mut fields = [0; 13];
        for (field, value) in fields.iter_mut().zip(header[6..].as_chunks::<8>().0) {
            *field = numeric(value, 16)?;
        }
        let [
            _,
            mode,
            user,
            group,
            links,
            _,
            size,
            _,
            _,
            device_major,
            device_minor,
            name_size,
            check,
        ] = fields;
        if user != 0
            || group != 0
            || device_major != 0
            || device_minor != 0
            || check != 0
            || !(1..=512).contains(&name_size)
            || mode & !0o177777 != 0
        {
            return Err(invalid("Invalid cpio ownership or bounds"));
        }
        let name_end = 110 + name_size as usize;
        let name = bytes
            .get(110..name_end)
            .and_then(|name| name.strip_suffix(&[0]))
            .ok_or_else(|| invalid("Truncated cpio name"))?;
        bytes = bytes
            .get(name_end.next_multiple_of(4)..)
            .ok_or_else(|| invalid("Truncated cpio name padding"))?;
        if name == b"TRAILER!!!" {
            if size != 0 || bytes.iter().any(|byte| *byte != 0) {
                return Err(invalid("Trailing cpio data"));
            }
            return Ok(files);
        }
        let path = path_name(value(name)?)?;
        let directory = match mode & 0o170000 {
            0o100000 if links == 1 => false,
            0o040000 if size == 0 && mode & 0o7000 == 0 => true,
            _ => return Err(invalid("Unsupported cpio entry or hard link")),
        };
        let size = size as usize;
        let data = bytes
            .get(..size)
            .ok_or_else(|| invalid("Truncated package cpio entry"))?;
        if path.is_empty() {
            return Err(invalid("Invalid cpio path"));
        }
        add_entry(&mut files, path, mode & 0o7777, data, directory)?;
        bytes = bytes
            .get(size.next_multiple_of(4)..)
            .ok_or_else(|| invalid("Truncated package cpio padding"))?;
    }
    Err(invalid("Missing package cpio terminator"))
}

fn verify(mut inventory: Inventory<'_>, expected: &[File]) -> io::Result<()> {
    let mut directories = BTreeSet::from([""]);
    for file in expected {
        let mut prefix = file.path.as_str();
        while let Some((parent, _)) = prefix.rsplit_once('/') {
            directories.insert(parent);
            prefix = parent;
        }
        let entry = inventory.remove(&file.path);
        if !entry.is_some_and(|entry| {
            !entry.directory && entry.mode == file.mode && digest(entry.data) == file.sha256
        }) {
            return Err(invalid("Package payload mismatch"));
        }
    }
    if inventory.iter().any(|(path, entry)| {
        !entry.directory || entry.mode != 0o755 || !directories.contains(path.as_str())
    }) {
        return Err(invalid("Unexpected package files"));
    }
    Ok(())
}

pub fn verify_tar(data: &[u8], expected: &[File]) -> io::Result<()> {
    verify(tar(data)?, expected)
}

pub fn verify_cpio(data: &[u8], expected: &[File]) -> io::Result<()> {
    verify(cpio(data)?, expected)
}

pub fn verify_compact(source: impl Read, output: impl Write) -> io::Result<()> {
    let compressed = read_bounded(source, BUNDLE_BYTES)?;
    let archive = read_bounded(MultiGzDecoder::new(compressed.as_slice()), BUNDLE_BYTES)?;
    let entries = tar(&archive)?;
    if entries.len() > 128 {
        return Err(invalid("Too many verification archive files"));
    }
    let mut metadata = Vec::with_capacity(entries.len());
    for (name, entry) in entries {
        let flat = name.len() <= 100
            && name
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'));
        if !flat
            || entry.directory
            || entry.mode != 0o644
            || [".deb", ".rpm", ".tar.gz"]
                .iter()
                .any(|extension| name.ends_with(extension))
        {
            return Err(invalid("Invalid verification archive entry"));
        }
        metadata.push((name, STANDARD.encode(entry.data)));
    }
    serde_json::to_writer(output, &metadata).map_err(io::Error::other)
}
