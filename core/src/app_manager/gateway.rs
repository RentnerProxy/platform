use super::{bad, journal::Slot};
use crate::app_ipc::filesystem::{bridge_authorization, connect_peer};
use bytes::Bytes;
use http_body_util::Full;
use hyper::{
    Request, StatusCode,
    client::conn::http1,
    header::{self, HeaderValue},
};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use std::{
    io,
    path::{Path, PathBuf},
    time::Duration,
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::time::{Instant, timeout};

#[derive(Clone)]
pub(super) struct Gateway {
    authorization: HeaderValue,
    socket: PathBuf,
    uid: u32,
}

pub(super) fn identity(id: &str, slot: &Slot) -> Value {
    json!({"appId":slot.app_id,"installationId":id,"generation":slot.generation,"uid":slot.uid})
}

pub(super) fn lease(identity: &Value) -> io::Result<(Value, Instant)> {
    let issued = Instant::now();
    let now = OffsetDateTime::now_utc();
    let expiry = (now + time::Duration::seconds(90))
        .replace_nanosecond(0)
        .map_err(io::Error::other)?;
    let timestamp = expiry.format(&Rfc3339).map_err(io::Error::other)?;
    let prefix = timestamp
        .strip_suffix('Z')
        .ok_or_else(|| bad("Invalid lease clock"))?;
    Ok((
        json!({"identity":identity,"leaseExpiresAt":format!("{prefix}.000Z")}),
        issued + (expiry - now).unsigned_abs(),
    ))
}

impl Gateway {
    pub fn open() -> io::Result<Self> {
        let token = std::env::var_os(crate::config::CONTROLLER_TOKEN_FILE_ENV)
            .ok_or_else(|| bad("Missing controller token file"))?;
        Ok(Self {
            authorization: bridge_authorization(Path::new(&token))?,
            socket: "/run/rentnerproxy/app-api/web.sock".into(),
            uid: 10002,
        })
    }
    #[cfg(test)]
    pub(super) fn fixture(socket: PathBuf, uid: u32) -> Self {
        Self {
            authorization: HeaderValue::from_static("Bearer fixture"),
            socket,
            uid,
        }
    }
    pub async fn post(&self, action: &'static str, body: Value) -> io::Result<()> {
        timeout(Duration::from_secs(6), async {
            let socket = connect_peer(&self.socket, self.uid).await?;
            let (mut sender, connection) = http1::Builder::new()
                .max_headers(32)
                .max_buf_size(16384)
                .handshake(TokioIo::new(socket))
                .await
                .map_err(io::Error::other)?;
            let request = Request::post(format!("/internal/v1/app-generations/{action}"))
                .header(header::HOST, "localhost")
                .header(header::CONNECTION, "close")
                .header(header::AUTHORIZATION, &self.authorization)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(serde_json::to_vec(&body)?)))
                .map_err(io::Error::other)?;
            let response = sender.send_request(request);
            tokio::pin!(response);
            let response = tokio::select! {
                response = &mut response => response,
                closed = connection => {
                    closed.map_err(io::Error::other)?;
                    response.await
                },
            }
            .map_err(io::Error::other)?;
            if response.status() != StatusCode::NO_CONTENT {
                let status = response.status();
                let kind = if status.is_server_error()
                    || matches!(
                        status,
                        StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_MANY_REQUESTS
                    ) {
                    io::ErrorKind::WouldBlock
                } else {
                    io::ErrorKind::PermissionDenied
                };
                return Err(io::Error::new(
                    kind,
                    format!(
                        "Generation {action} rejected ({})",
                        response.status().as_u16()
                    ),
                ));
            }
            Ok(())
        })
        .await?
    }
}
