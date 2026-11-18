use std::process::ExitCode;

use rentnerproxy_controller::{healthcheck, run};

fn main() -> ExitCode {
    let mut arguments = std::env::args().skip(1);
    let command = arguments.next();
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
