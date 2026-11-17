use crate::{
    CONTEXT, CONTEXT_REJECTED, GENERATION, INSTALLATION, IO_TIMEOUT, ManagerContext, NOTIFICATIONS,
    Result, read_bounded, validate_credential,
};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    HeaderMap, Method, Request, Response, StatusCode,
    body::{Bytes, Incoming},
    header::{AUTHORIZATION, CONTENT_TYPE},
    http::header::AsHeaderName,
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde_json::{Value, json};
use std::{convert::Infallible, fs, io, os::unix::fs::PermissionsExt, sync::Arc, time::Duration};
use tokio::{
    net::{UnixListener, UnixStream},
    sync::Semaphore,
    time::timeout,
};

fn header_matches(headers: &HeaderMap, name: impl AsHeaderName, expected: &str) -> bool {
    let values = headers.get_all(name);
    let mut values = values.iter();
    values
        .next()
        .is_some_and(|value| value.as_bytes() == expected.as_bytes())
        && values.next().is_none()
}

fn generation_current(context: &ManagerContext) -> bool {
    read_bounded(&context.active_generation_file, 128)
        .ok()
        .and_then(|raw| String::from_utf8(raw).ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        == Some(context.app.generation)
}

async fn respond(
    context: &ManagerContext,
    peer_uid: u32,
    request: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let headers = request.headers();
    let app = &context.app;
    let (status, body) = if peer_uid != context.app_uid
        || !header_matches(headers, INSTALLATION, &app.installation_id)
        || !header_matches(headers, GENERATION, &app.generation.to_string())
        || !header_matches(
            headers,
            AUTHORIZATION,
            &format!("Bearer {}", app.core_credential),
        )
        || !generation_current(context)
    {
        (StatusCode::FORBIDDEN, json!({ "error": CONTEXT_REJECTED }))
    } else {
        let route = request.uri().path_and_query().map(|route| route.as_str());
        match (request.method(), route) {
            (&Method::GET, Some(CONTEXT)) => (
                StatusCode::OK,
                json!({ "installationId": app.installation_id, "generation": app.generation }),
            ),
            (&Method::POST, Some(NOTIFICATIONS)) => {
                // Consume the bounded request body before reusing the connection.
                let body = timeout(
                    IO_TIMEOUT,
                    Limited::new(request.into_body(), 4096).collect(),
                )
                .await
                .ok()
                .and_then(|result| result.ok())
                .and_then(|body| serde_json::from_slice::<Value>(&body.to_bytes()).ok());
                if body != Some(json!({ "message": "fixture" })) {
                    (
                        StatusCode::BAD_REQUEST,
                        json!({ "error": "invalidFixtureBody" }),
                    )
                } else if generation_current(context) {
                    (StatusCode::ACCEPTED, json!({ "accepted": true }))
                } else {
                    (StatusCode::FORBIDDEN, json!({ "error": CONTEXT_REJECTED }))
                }
            }
            _ => (StatusCode::FORBIDDEN, json!({ "error": "scopeDenied" })),
        }
    };
    json_response(status, body)
}

fn json_response(status: StatusCode, body: Value) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(body.to_string())));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/json"),
    );
    response
}

pub(super) async fn serve(context: ManagerContext) -> Result<()> {
    validate_credential(&context.app.core_credential)?;
    // A local socket pair gives the process UID through the same kernel API as accepted peers.
    if UnixStream::pair()?.0.peer_cred()?.uid() != context.broker_uid {
        return Err(io::Error::other("Broker must run under the configured UID").into());
    }
    let socket = UnixListener::bind(&context.app.core_socket)?;
    fs::set_permissions(&context.app.core_socket, fs::Permissions::from_mode(0o660))?;

    let context = Arc::new(context);
    let capacity = Arc::new(Semaphore::new(16));
    loop {
        let permit = capacity.clone().acquire_owned().await?;
        let (stream, _) = socket.accept().await?;
        let Ok(credential) = stream.peer_cred() else {
            continue;
        };
        let peer_uid = credential.uid();
        let context = context.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let service = service_fn(move |request| {
                let context = context.clone();
                async move { Ok::<_, Infallible>(respond(&context, peer_uid, request).await) }
            });
            let _ = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(35))
                .max_buf_size(8192)
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}
