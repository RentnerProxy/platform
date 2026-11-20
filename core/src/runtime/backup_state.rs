use std::{
    io::{self, Read},
    process::ExitCode,
};

use super::{certificates, dns_connections};

pub fn run_check_backup_state(mut arguments: impl Iterator<Item = String>) -> ExitCode {
    let (Some(kind), None) = (arguments.next(), arguments.next()) else {
        return ExitCode::FAILURE;
    };
    if check(&kind, io::stdin().lock()).unwrap_or(false) {
        ExitCode::SUCCESS
    } else {
        eprintln!("Invalid controller metadata in backup");
        ExitCode::FAILURE
    }
}

fn check(kind: &str, input: impl Read) -> io::Result<bool> {
    let (maximum, validate): (usize, fn(&[u8]) -> bool) = match kind {
        "dns-registry" => (1024 * 1024, dns_connections::valid_backup_registry),
        "certificate-index" => (8 * 1024 * 1024, certificates::valid_backup_index),
        _ => return Ok(false),
    };
    let mut bytes = Vec::new();
    input.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    Ok(bytes.len() <= maximum && validate(&bytes))
}

#[cfg(test)]
#[path = "../../tests/private/backup_state.rs"]
mod tests;
