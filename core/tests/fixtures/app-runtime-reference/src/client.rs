use crate::{
    AppContext, CallOptions, GENERATION, INSTALLATION, IO_TIMEOUT, Result, validate_credential,
};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    Method, Request, StatusCode,
    body::Bytes,
    client::conn::http1::{self, SendRequest},
    header::{AUTHORIZATION, CONTENT_TYPE, HOST},
    http::uri::PathAndQuery,
};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use std::{io, path::Path};
use tokio::{net::UnixStream, task::JoinHandle, time::timeout};

pub(super) struct Connection {
    sender: SendRequest<Full<Bytes>>,
    driver: JoinHandle<()>,
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

pub(super) struct Reply {
    pub(super) status: StatusCode,
    pub(super) body: Value,
}

pub(super) async fn connect(
    socket: &Path,
    expected_uid: u32,
    wrong_peer: bool,
) -> Result<Option<Connection>> {
    let stream = timeout(IO_TIMEOUT, UnixStream::connect(socket)).await??;
    let actual_uid = stream.peer_cred()?.uid();
    if wrong_peer && actual_uid != expected_uid {
        println!(
            "{}",
            json!({
                "error": "peerUidRejected",
                "expectedUid": expected_uid,
                "actualUid": actual_uid
            })
        );
        return Ok(None);
    }
    if actual_uid != expected_uid || wrong_peer {
        return Err(io::Error::other("Unexpected fixture peer UID").into());
    }
    let (sender, connection) =
        timeout(IO_TIMEOUT, http1::handshake(TokioIo::new(stream))).await??;
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(Some(Connection { sender, driver }))
}

pub(super) async fn send(
    connection: &mut Connection,
    context: &AppContext,
    credential: &str,
    method: Method,
    path: PathAndQuery,
    options: &CallOptions,
) -> Result<Reply> {
    let installation = options
        .installation_id
        .as_deref()
        .unwrap_or(&context.installation_id);
    let generation = options.generation.unwrap_or(context.generation).to_string();
    let mut bearer = format!("Bearer {credential}");
    if options.wrong_credential {
        let offset = "Bearer ".len();
        let replacement = if bearer.as_bytes()[offset] == b'0' {
            "1"
        } else {
            "0"
        };
        bearer.replace_range(offset..offset + 1, replacement);
    }
    let mut builder = Request::builder()
        .method(method)
        .uri(path.as_str())
        .header(HOST, "localhost")
        .header(AUTHORIZATION, bearer)
        .header(INSTALLATION, installation)
        .header(GENERATION, generation);
    let body = match &options.body {
        Some(body) => {
            builder = builder.header(CONTENT_TYPE, "application/json");
            Bytes::from(serde_json::to_vec(body)?)
        }
        None => Bytes::new(),
    };
    let request = builder.body(Full::new(body))?;
    timeout(IO_TIMEOUT, async {
        connection.sender.ready().await?;
        let response = connection.sender.send_request(request).await?;
        let status = response.status();
        let bytes = Limited::new(response.into_body(), 16384)
            .collect()
            .await?
            .to_bytes();
        let body = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        Ok(Reply { status, body })
    })
    .await?
}

pub(super) async fn call(
    socket: &Path,
    expected_uid: u32,
    context: &AppContext,
    credential: &str,
    method: Method,
    path: PathAndQuery,
    options: CallOptions,
) -> Result<()> {
    validate_credential(credential)?;
    if let Some(mut connection) = connect(socket, expected_uid, options.wrong_peer).await? {
        let response = send(&mut connection, context, credential, method, path, &options).await?;
        println!(
            "{}",
            json!({ "status": response.status.as_u16(), "body": response.body })
        );
    }
    Ok(())
}
