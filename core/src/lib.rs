#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub mod app_backup;
pub mod app_install;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod app_ipc;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub mod app_manager;
#[cfg(target_os = "linux")]
pub(crate) mod appliance_process;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub mod appliance_supervisor;
mod application;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod backup_envelope;
mod config;
mod models;
mod npm_import;
mod pem;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod protected_files;
mod proxy;
mod runtime;
mod server;
mod shutdown;
mod version;

pub use application::{healthcheck, run};
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub use backup_envelope::run_backup_envelope;
pub use npm_import::run_read_npm_sqlite;
pub use runtime::run_check_backup_state;

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub use app_ipc::{run_app_ipc, run_app_provision, run_app_watchdog};
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub use protected_files::run_write_bootstrap_state;

#[cfg(test)]
#[path = "../tests/private/mod.rs"]
mod tests;
