mod crowdsec;
mod drain;
mod process;
mod restart;

use crate::appliance_process::{Consumers, verify_consumers_stopped};
use std::{io, process::ExitCode};

fn dispatch(command: &str, args: &[String]) -> io::Result<()> {
    match (command, args) {
        ("crowdsec", []) => crowdsec::serve(),
        ("protect-capi", []) => crowdsec::protect_capi(),
        ("drain", args) => drain::run(args),
        ("reserve-web-restart", args) => restart::run(args),
        ("verify-web", []) => verify_consumers_stopped(Consumers::Web, None, None),
        ("verify-backup", [mode, valkey, caddy]) => {
            let preserve_web = match mode.as_str() {
                "preserve-web" => true,
                "all" => false,
                _ => return Err(io::Error::other("Invalid backup consumer mode")),
            };
            let caddy = if caddy == "0" {
                None
            } else {
                Some(process::pid(caddy)? as u32)
            };
            let valkey = process::pid(valkey)?;
            let owned_valkey = process::owned_pid(valkey, unsafe { libc::getppid() }, None)?;
            let retained_caddy = caddy.map(|pid| process::open_pid(pid as i32)).transpose()?;
            verify_consumers_stopped(
                Consumers::Backup { preserve_web },
                Some(valkey as u32),
                caddy,
            )?;
            for task in std::iter::once(&owned_valkey).chain(retained_caddy.as_ref()) {
                if drain::exited(task)? {
                    return Err(io::Error::other(
                        "Exempted maintenance process stopped during scan",
                    ));
                }
            }
            Ok(())
        }
        _ => Err(io::Error::other("Invalid appliance supervisor command")),
    }
}

pub fn run(mut arguments: impl Iterator<Item = String>) -> ExitCode {
    let command = arguments.next().unwrap_or_default();
    match dispatch(&command, &arguments.collect::<Vec<_>>()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("[rentnerproxy:supervisor] {error}");
            ExitCode::FAILURE
        }
    }
}
