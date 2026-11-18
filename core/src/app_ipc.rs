mod filesystem;
mod gateway;
mod process;
mod wire_json;

use std::{
    env, io,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
    time::Duration,
};

use aws_lc_rs::{digest, rand};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hyper::header::HeaderValue;
use serde::{Deserialize, Serialize};
use tokio::{process::Child, time::timeout};

const APP_ROOT: &str = "/run/rentnerproxy/apps";
const GATEWAY_SOCKET: &str = "/run/rentnerproxy/app-api/web.sock";
const WEB_UID: u32 = 10002;
const PROFILE: &str = "rentnerproxy-linux-v1";
const VERSION: &str = "1.0.0";
const LAUNCH_TIMEOUT: Duration = Duration::from_secs(10);
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_LEASE_SECONDS: u64 = 7 * 24 * 60 * 60;

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct LaunchConfig {
    app_id: String,
    installation_id: String,
    generation: u64,
    uid: u32,
    gid: u32,
    executable: PathBuf,
    data_directory: PathBuf,
    database_url_file: Option<PathBuf>,
    lease_seconds: u64,
    runtime_profile: String,
    app_protocol: String,
    platform_api: String,
    ui_bridge: Option<String>,
}

impl LaunchConfig {
    fn validate(&self) -> io::Result<()> {
        if self.runtime_profile != PROFILE
            || !supports_version(&self.app_protocol)
            || !supports_version(&self.platform_api)
            || self
                .ui_bridge
                .as_deref()
                .is_some_and(|range| !supports_version(range))
        {
            return Err(io::Error::other(
                "Unsupported app runtime profile or protocol range",
            ));
        }
        let app_id_valid = self
            .app_id
            .split_once('.')
            .is_some_and(|(namespace, app)| valid_slug(namespace, 32) && valid_slug(app, 64));
        if !app_id_valid
            || !record_id(&self.installation_id)
            || !(1..=9_007_199_254_740_991).contains(&self.generation)
            || !(20_000..=59_999).contains(&self.uid)
            || self.gid != self.uid
            || !(1..=MAX_LEASE_SECONDS).contains(&self.lease_seconds)
        {
            return Err(io::Error::other("Invalid app launch identity or lease"));
        }
        filesystem::validate_child_paths(self)
    }
}

fn valid_slug(value: &str, max: usize) -> bool {
    let bytes = value.as_bytes();
    bytes.len() <= max
        && bytes.first().is_some_and(u8::is_ascii_lowercase)
        && bytes
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn record_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() <= 64
        && bytes
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(*byte, b'-' | b'_')
        })
}

fn supports_version(range: &str) -> bool {
    let Some(max) = range.strip_prefix(">=1.0.0 <") else {
        return false;
    };
    if max == "2.0.0" {
        return true;
    }
    max.strip_prefix("1.")
        .and_then(|max| max.split_once('.'))
        .is_some_and(|(minor, patch)| {
            [minor, patch].iter().all(|part| {
                part.len() <= 6
                    && !part.is_empty()
                    && part.bytes().all(|byte| byte.is_ascii_digit())
                    && (part.len() == 1 || !part.starts_with('0'))
            }) && (minor != "0" || patch != "0")
        })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Versions {
    app_protocol: &'static str,
    platform_api: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    ui_bridge: Option<&'static str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Bootstrap<'a> {
    format_version: u8,
    app_id: &'a str,
    installation_id: &'a str,
    generation: u64,
    runtime_profile: &'static str,
    versions: Versions,
    app_socket: &'a Path,
    core_socket: &'a Path,
    app_credential: &'a str,
    core_credential: &'a str,
}

fn credential() -> io::Result<String> {
    let mut entropy = [0; 32];
    rand::fill(&mut entropy).map_err(|_| io::Error::other("Unable to issue app credential"))?;
    Ok(URL_SAFE_NO_PAD.encode(entropy))
}

/// Supervise one native installation generation on a private inherited manager pipe.
pub async fn run_app_ipc() -> ExitCode {
    if let Err(error) = run().await {
        eprintln!("App IPC stopped: {error}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

async fn run() -> io::Result<()> {
    let manager = process::ManagerPipe::open()?;
    let config = timeout(LAUNCH_TIMEOUT, manager.launch()).await??;
    config.validate()?;
    let token_path = env::var_os(crate::config::CONTROLLER_TOKEN_FILE_ENV)
        .ok_or_else(|| io::Error::other("Missing protected controller token file"))?;
    let token = filesystem::bridge_authorization(Path::new(&token_path))?;
    let stop = async {
        tokio::select! {
            _ = manager.revoked() => {},
            _ = crate::shutdown::wait_for_shutdown() => {},
        }
    };
    run_generation(
        config,
        Path::new(APP_ROOT),
        Path::new(GATEWAY_SOCKET),
        WEB_UID,
        token,
        stop,
    )
    .await
}

async fn run_generation(
    config: LaunchConfig,
    app_root: &Path,
    gateway_socket: &Path,
    gateway_uid: u32,
    token: HeaderValue,
    stop: impl Future<Output = ()>,
) -> io::Result<()> {
    let (sockets, listener) = filesystem::GenerationSockets::bind(app_root, &config)?;
    let core_credential = credential()?;
    let mut app_credential = credential()?;
    while core_credential == app_credential {
        app_credential = credential()?;
    }
    let bootstrap = Bootstrap {
        format_version: 1,
        app_id: &config.app_id,
        installation_id: &config.installation_id,
        generation: config.generation,
        runtime_profile: PROFILE,
        versions: Versions {
            app_protocol: VERSION,
            platform_api: VERSION,
            ui_bridge: config.ui_bridge.as_ref().map(|_| VERSION),
        },
        app_socket: &sockets.app_socket,
        core_socket: &sockets.core_socket,
        app_credential: &app_credential,
        core_credential: &core_credential,
    };
    let descriptor = serde_json::to_vec(&bootstrap)
        .map_err(|_| io::Error::other("Unable to encode app bootstrap descriptor"))?;
    let state = Arc::new(gateway::Generation::new(
        &config,
        digest::digest(&digest::SHA256, core_credential.as_bytes()),
        gateway_socket.to_owned(),
        gateway_uid,
        token,
    )?);
    let mut child = process::start_child(&config)?;
    let pid = child
        .id()
        .ok_or_else(|| io::Error::other("App child has no process ID"))?;

    let mut ready = false;
    let child_exited = tokio::select! {
        biased;
        _ = stop => Ok(false),
        _ = tokio::time::sleep(Duration::from_secs(config.lease_seconds)) => Ok(false),
        result = process::observe_exit(pid) => result.map(|()| true),
        result = gateway::serve(listener, state) => result.map(|()| false),
        result = supervise(&mut child, descriptor, &bootstrap, config.uid, &mut ready) => result.map(|()| false),
    };
    let status = process::stop_child(pid, &mut child).await;
    if child_exited? {
        process::app_exit(status?)?;
        if !ready {
            return Err(io::Error::other("Native app exited before readiness"));
        }
        Ok(())
    } else {
        status.map(|_| ())
    }
}

async fn supervise(
    child: &mut Child,
    descriptor: Vec<u8>,
    bootstrap: &Bootstrap<'_>,
    uid: u32,
    ready: &mut bool,
) -> io::Result<()> {
    timeout(
        LAUNCH_TIMEOUT,
        process::deliver_bootstrap(child, &descriptor),
    )
    .await??;
    timeout(STARTUP_TIMEOUT, gateway::app_ready(bootstrap, uid)).await??;
    // The supervisor consumes this line. App stdout and stderr are discarded.
    use std::io::Write as _;
    writeln!(io::stdout().lock(), "ready")?;
    *ready = true;
    std::future::pending().await
}

#[cfg(test)]
#[path = "../tests/private/app_ipc.rs"]
mod tests;
