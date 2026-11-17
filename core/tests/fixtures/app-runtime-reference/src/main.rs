mod broker;
mod client;

use hyper::{Method, StatusCode, http::uri::PathAndQuery};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{
    env,
    fs::File,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    thread,
    time::Duration,
};
use tokio::{sync::oneshot, time::timeout};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

const IO_TIMEOUT: Duration = Duration::from_secs(5);
const INSTALLATION: &str = "x-app-installation";
const GENERATION: &str = "x-app-generation";
const CONTEXT: &str = "/platform/v1/context";
const NOTIFICATIONS: &str = "/platform/v1/notifications";
const CONTEXT_REJECTED: &str = "installationContextRejected";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AppContext {
    core_socket: PathBuf,
    installation_id: String,
    generation: u64,
    core_credential: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ManagerContext {
    #[serde(flatten)]
    app: AppContext,
    app_socket: PathBuf,
    app_credential: String,
    app_uid: u32,
    broker_uid: u32,
    active_generation_file: PathBuf,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CallOptions {
    #[serde(default, deserialize_with = "deserialize_body")]
    body: Option<Value>,
    installation_id: Option<String>,
    generation: Option<u64>,
    #[serde(default)]
    wrong_credential: bool,
    #[serde(default)]
    wrong_peer: bool,
}

fn deserialize_body<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<Value>, D::Error> {
    Value::deserialize(deserializer).map(Some)
}

fn read_bounded(path: &Path, max_bytes: u64) -> io::Result<Vec<u8>> {
    let mut raw = Vec::new();
    File::open(path)?
        .take(max_bytes + 1)
        .read_to_end(&mut raw)?;
    if raw.len() as u64 > max_bytes {
        return Err(io::Error::other("Fixture file exceeds its size limit"));
    }
    Ok(raw)
}

fn read_context<T: DeserializeOwned>(path: &str) -> Result<T> {
    let raw = read_bounded(Path::new(path), 8192)?;
    serde_json::from_slice(&raw).map_err(|_| io::Error::other("Invalid fixture descriptor").into())
}

fn validate_credential(credential: &str) -> Result<()> {
    if credential.len() != 64
        || !credential
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(io::Error::other("Invalid fixture credential").into());
    }
    Ok(())
}

fn request_options(tail: &[String]) -> Result<CallOptions> {
    match tail {
        [] => Ok(CallOptions::default()),
        [options] if options.len() <= 16384 => serde_json::from_str(options)
            .map_err(|_| io::Error::other("Invalid fixture request options").into()),
        _ => Err(io::Error::other("Expected optional fixture request options").into()),
    }
}

async fn notify(
    connection: &mut client::Connection,
    context: &AppContext,
) -> Result<client::Reply> {
    client::send(
        connection,
        context,
        &context.core_credential,
        Method::POST,
        PathAndQuery::from_static(NOTIFICATIONS),
        &CallOptions {
            body: Some(json!({ "message": "fixture" })),
            ..Default::default()
        },
    )
    .await
}

async fn hold_core(context: AppContext, broker_uid: u32) -> Result<()> {
    validate_credential(&context.core_credential)?;
    let mut connection = client::connect(&context.core_socket, broker_uid, false)
        .await?
        .ok_or_else(|| io::Error::other("Expected a verified broker connection"))?;
    let response = notify(&mut connection, &context).await?;
    if response.status != StatusCode::ACCEPTED || response.body != json!({ "accepted": true }) {
        return Err(
            io::Error::other("Expected the initial fixture mutation to be accepted").into(),
        );
    }

    let (signal, received) = oneshot::channel();
    thread::spawn(move || {
        let mut byte = [0];
        let result = io::stdin().read_exact(&mut byte).map(|()| byte == *b"\n");
        let _ = signal.send(result);
    });
    println!("ready");
    io::stdout().flush()?;
    if !timeout(Duration::from_secs(30), received).await??? {
        return Err(io::Error::other("Expected a newline before checking revocation").into());
    }

    let response = notify(&mut connection, &context).await?;
    if response.status != StatusCode::FORBIDDEN
        || response.body != json!({ "error": CONTEXT_REJECTED })
    {
        return Err(io::Error::other("Expected the held fixture mutation to be revoked").into());
    }
    println!("revoked");
    io::stdout().flush()?;
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args: Vec<_> = env::args().skip(1).collect();
    match args.as_slice() {
        [command, descriptor] if command == "serve" => {
            broker::serve(read_context(descriptor)?).await
        }
        [command, descriptor, method, path, options @ ..] if command == "call-app" => {
            let context: ManagerContext = read_context(descriptor)?;
            if !matches!(
                (method.as_str(), path.as_str()),
                ("GET", "/app/v1/ready") | ("POST", "/app/v1/probe")
            ) {
                return Err(io::Error::other("Unknown fixture app route").into());
            }
            client::call(
                &context.app_socket,
                context.app_uid,
                &context.app,
                &context.app_credential,
                method.parse()?,
                path.parse()?,
                request_options(options)?,
            )
            .await
        }
        [command, descriptor, uid, method, path, options @ ..] if command == "call-core" => {
            let context: AppContext = read_context(descriptor)?;
            let path: PathAndQuery = path.parse()?;
            if !path.path().starts_with('/') {
                return Err(io::Error::other("Expected an absolute fixture request path").into());
            }
            client::call(
                &context.core_socket,
                uid.parse()?,
                &context,
                &context.core_credential,
                method.parse()?,
                path,
                request_options(options)?,
            )
            .await
        }
        [command, descriptor, uid] if command == "hold-core" => {
            hold_core(read_context(descriptor)?, uid.parse()?).await
        }
        _ => Err(io::Error::other("Expected serve, call-app, call-core or hold-core").into()),
    }
}
