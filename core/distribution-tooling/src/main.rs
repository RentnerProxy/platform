mod archive;
mod evidence;
mod package;

use std::io::{self, Read};
use std::path::{Path, PathBuf};

use marketplace_artifacts::{invalid, parse_json};
use serde::de::DeserializeOwned;

const BUNDLE_BYTES: u64 = 16 * 1024 * 1024;

fn read_bounded(source: impl Read, maximum: u64) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    source.take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(invalid("Distribution input exceeds its byte limit"));
    }
    Ok(bytes)
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> io::Result<T> {
    serde_json::from_value(parse_json(bytes)?)
        .map_err(|_| invalid("Invalid distribution verification data"))
}

fn request<T: DeserializeOwned>() -> io::Result<T> {
    decode(&read_bounded(io::stdin().lock(), 128 * 1024)?)
}

fn input_path(path: &Path) -> io::Result<&Path> {
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(invalid("Expected an absolute distribution path"))
    }
}

fn run() -> io::Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && args[0] == "compact" {
        return archive::verify_compact(io::stdin().lock(), io::stdout().lock());
    }
    let [action, path] = args.as_slice() else {
        return Err(invalid(
            "Expected a distribution verification command and path",
        ));
    };
    let path = PathBuf::from(path);
    let path = input_path(&path)?;
    match action.to_str() {
        Some("package") => package::verify(path, request()?),
        Some("oci-input") => evidence::verify_oci_input(path, request()?, io::stdout().lock()),
        Some("reports") => evidence::verify_reports(path, request()?),
        Some("bound") => evidence::verify_bound(path, request()?, io::stdout().lock()),
        _ => Err(invalid("Unknown distribution verification command")),
    }
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            if error.kind() == io::ErrorKind::InvalidData {
                eprintln!("{error}");
            } else {
                eprintln!("Distribution input or verification tool is unavailable");
            }
            std::process::ExitCode::FAILURE
        }
    }
}
