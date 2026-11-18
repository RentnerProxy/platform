#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod app_ipc;
mod application;
mod config;
mod models;
mod pem;
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
pub use app_ipc::run_app_ipc;

#[cfg(test)]
#[path = "../tests/private/mod.rs"]
mod tests;
