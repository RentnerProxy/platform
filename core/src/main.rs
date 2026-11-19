use std::process::ExitCode;

use rentnerproxy_controller::{healthcheck, run};

fn main() -> ExitCode {
    let mut arguments = std::env::args().skip(1);
    let command = arguments.next();
    if command.as_deref() == Some("--check-backup-state") {
        return rentnerproxy_controller::run_check_backup_state(arguments);
    }
    if command.as_deref() == Some("--backup-envelope") {
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        return rentnerproxy_controller::run_backup_envelope(arguments);
        #[cfg(not(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )))]
        return ExitCode::FAILURE;
    }
    if command.as_deref() == Some("--read-npm-sqlite") {
        return rentnerproxy_controller::run_read_npm_sqlite(arguments);
    }
    if command.as_deref() == Some("--app-backup") {
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        return rentnerproxy_controller::app_backup::run(arguments);
        #[cfg(not(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )))]
        return ExitCode::FAILURE;
    }
    if command.as_deref() == Some("--app-stage") {
        return rentnerproxy_controller::app_install::run_app_stage(arguments);
    }
    if command.as_deref() == Some("--appliance-supervisor") {
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        return rentnerproxy_controller::appliance_supervisor::run(arguments);
        #[cfg(not(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )))]
        return ExitCode::FAILURE;
    }
    if command.as_deref() == Some("--write-bootstrap-state") {
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        return rentnerproxy_controller::run_write_bootstrap_state(arguments);
        #[cfg(not(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )))]
        return ExitCode::FAILURE;
    }
    if command.as_deref() == Some("--app-ipc-watchdog") {
        if arguments.next().is_some() {
            return ExitCode::FAILURE;
        }
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        return rentnerproxy_controller::run_app_watchdog();
        #[cfg(not(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )))]
        return ExitCode::FAILURE;
    }
    run_command(command, arguments)
}

#[tokio::main]
async fn run_command(
    command: Option<String>,
    mut arguments: impl Iterator<Item = String>,
) -> ExitCode {
    if let Some(app_command @ ("--app-manager" | "--app-control")) = command.as_deref() {
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        return if app_command == "--app-manager" {
            rentnerproxy_controller::app_manager::run_app_manager(arguments).await
        } else {
            rentnerproxy_controller::app_manager::run_app_control(arguments).await
        };
        #[cfg(not(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )))]
        {
            eprintln!("{app_command} requires Linux AMD64 or ARM64");
            return ExitCode::FAILURE;
        }
    }
    if command.as_deref() == Some("--app-provision") {
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        return rentnerproxy_controller::run_app_provision(arguments).await;
        #[cfg(not(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )))]
        return ExitCode::FAILURE;
    }
    if command.as_deref() == Some("--app-ipc") {
        if arguments.next().is_some() {
            eprintln!("App IPC takes its launch request from the manager pipe");
            return ExitCode::FAILURE;
        }
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        return rentnerproxy_controller::run_app_ipc().await;
        #[cfg(not(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )))]
        {
            eprintln!("App IPC requires Linux AMD64 or ARM64");
            return ExitCode::FAILURE;
        }
    }
    if command.as_deref() == Some("--healthcheck") {
        let endpoint = arguments.next().unwrap_or_else(|| "ready".to_owned());
        return healthcheck(&endpoint).await;
    }

    run().await
}
