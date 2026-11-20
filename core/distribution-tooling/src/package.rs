use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::io::{self, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use flate2::read::MultiGzDecoder;
use marketplace_artifacts::{invalid, read_file};
use serde::Deserialize;

use crate::archive::{ARCHIVE_BYTES, File, verify_cpio, verify_tar};
use crate::{BUNDLE_BYTES, read_bounded};

#[derive(Deserialize)]
#[serde(tag = "format", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Package {
    Deb {
        payload: Vec<File>,
        control: Vec<File>,
    },
    Rpm {
        payload: Vec<File>,
        version: String,
        release: String,
        architecture: String,
        hooks: [String; 4],
    },
    Quadlet {
        payload: Vec<File>,
    },
}

const RPM_DEPENDENCIES: [&str; 10] = [
    "/bin/bash||",
    "bash||",
    "coreutils||",
    "util-linux||",
    "podman|>=|5.4",
    "systemd|>=|252",
    "rpmlib(CompressedFileNames)|<=|3.0.4-1",
    "rpmlib(FileDigests)|<=|4.6.0-1",
    "rpmlib(PayloadFilesHavePrefix)|<=|4.0-1",
    "rpmlib(PayloadIsXz)|<=|5.2-1",
];

fn package_tool(tool: &str, args: &[&OsStr], path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    let mut process = Command::new(tool)
        .args(args)
        .arg(path)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let output = read_bounded(process.stdout.take().expect("child stdout is piped"), limit);
    if output.is_err() {
        let _ = process.kill();
    }
    if !process.wait()?.success() {
        return Err(invalid("Distribution package reader failed"));
    }
    output
}

fn verify_transaction_tags(tags: &str) -> io::Result<()> {
    let mut has_name = false;
    for line in tags.lines() {
        let tag: u32 = line
            .parse()
            .map_err(|_| invalid("Invalid RPM header tag list"))?;
        match tag {
            1000 => has_name = true, // RPMTAG_NAME
            // PREUNTRANS, POSTUNTRANS and their interpreter and flags tags.
            5103..=5108 => return Err(invalid("Unexpected RPM execution hook")),
            _ => (),
        }
    }
    if !has_name {
        return Err(invalid("Incomplete RPM header tag list"));
    }
    Ok(())
}

fn rpm_header(
    path: &Path,
    payload: &[File],
    version: &str,
    release: &str,
    architecture: &str,
    hooks: &[String; 4],
) -> io::Result<()> {
    let query = |format: &str| {
        let result = package_tool(
            "rpm",
            &["-qp".as_ref(), "--qf".as_ref(), format.as_ref()],
            path,
            128 * 1024,
        )?;
        String::from_utf8(result).map_err(|_| invalid("Invalid RPM query output"))
    };
    let identity = query("%{NAME}\n%{VERSION}\n%{RELEASE}\n%{ARCH}\n%{EPOCH}")?;
    let expected = format!("rentnerproxy\n{version}\n{release}\n{architecture}");
    if !identity
        .rsplit_once('\n')
        .is_some_and(|(fields, epoch)| fields == expected && matches!(epoch, "(none)" | "0"))
    {
        return Err(invalid("RPM identity mismatch"));
    }
    let files = query(
        "[%{FILENAMES}|%{FILEMODES:octal}|%{FILEUSERNAME}|%{FILEGROUPNAME}|%{FILEFLAGS}|%{FILECAPS}|%{FILELINKTOS}\n]",
    )?;
    let files: Vec<_> = files.lines().collect();
    if files.len() != payload.len() {
        return Err(invalid("Unexpected RPM file header"));
    }
    for file in payload {
        let installed = format!("/{}", file.path);
        if !files.iter().any(|line| {
            let columns: Vec<_> = line.split('|').collect();
            matches!(columns.as_slice(), [path, mode, "root", "root", "0", "(none)", ""]
                if *path == installed && u32::from_str_radix(mode, 8) == Ok(0o100000 | file.mode))
        }) {
            return Err(invalid("Unsafe RPM file metadata"));
        }
    }
    let dependencies = query("[%{REQUIRENAME}|%{REQUIREFLAGS:depflags}|%{REQUIREVERSION}\n]")?;
    if dependencies.lines().collect::<BTreeSet<_>>() != BTreeSet::from(RPM_DEPENDENCIES)
        || !query("[%{CONFLICTNAME}\n]")?.is_empty()
    {
        return Err(invalid("Unexpected RPM dependencies"));
    }
    for (name, expected) in ["PREIN", "POSTIN", "PREUN", "POSTUN"].iter().zip(hooks) {
        if query(&format!("%{{{name}}}"))?.trim() != expected.trim()
            || query(&format!("[%{{{name}PROG}}]"))? != "/bin/bash"
        {
            return Err(invalid("Unexpected RPM scriptlet"));
        }
    }
    verify_transaction_tags(&query("[%{*:tagnum}\n]")?)?;
    for tag in [
        "PRETRANS",
        "POSTTRANS",
        "VERIFYSCRIPT",
        "TRIGGERSCRIPTS",
        "FILETRIGGERSCRIPTS",
        "TRANSFILETRIGGERSCRIPTS",
    ] {
        if !matches!(query(&format!("[%{{{tag}}}]"))?.trim(), "" | "(none)") {
            return Err(invalid("Unexpected RPM execution hook"));
        }
    }
    Ok(())
}

pub fn verify(path: &Path, package: Package) -> io::Result<()> {
    let bytes = read_file(path, BUNDLE_BYTES)?;
    if let Package::Quadlet { payload } = package {
        let archive = read_bounded(MultiGzDecoder::new(bytes.as_slice()), ARCHIVE_BYTES)?;
        return verify_tar(&archive, &payload);
    }
    let mut snapshot = tempfile::NamedTempFile::new()?;
    snapshot.write_all(&bytes)?;
    let path = snapshot.path();
    match package {
        Package::Deb { payload, control } => {
            let read_tar =
                |arg: &str| package_tool("dpkg-deb", &[arg.as_ref()], path, ARCHIVE_BYTES);
            verify_tar(&read_tar("--fsys-tarfile")?, &payload)?;
            verify_tar(&read_tar("--ctrl-tarfile")?, &control)
        }
        Package::Rpm {
            payload,
            version,
            release,
            architecture,
            hooks,
        } => {
            verify_cpio(
                &package_tool("rpm2cpio", &[], path, ARCHIVE_BYTES)?,
                &payload,
            )?;
            rpm_header(path, &payload, &version, &release, &architecture, &hooks)
        }
        Package::Quadlet { .. } => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::verify_transaction_tags;

    #[test]
    fn rejects_removal_transaction_tags_on_any_rpm_reader() {
        verify_transaction_tags("1000\n1001\n5102\n5109\n").unwrap();
        for tag in 5103..=5108 {
            assert!(verify_transaction_tags(&format!("1000\n{tag}\n")).is_err());
        }
        for incomplete in ["", "1001\n", "1000\nunknown\n"] {
            assert!(verify_transaction_tags(incomplete).is_err());
        }
    }
}
