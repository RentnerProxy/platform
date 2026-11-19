use std::{
    convert::Infallible,
    io,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use aws_lc_rs::{constant_time, digest};
use axum::body::Body;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::{
    Method, Request, Response, StatusCode, Version,
    body::{Body as HttpBody, Frame, Incoming},
    client,
    header::{self, HeaderMap, HeaderValue},
    server,
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use rentnerproxy_app_contracts::{HttpDescriptor, HttpMethod, HttpOperation};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::json;
use tokio::{
    net::UnixListener,
    task::{JoinHandle, JoinSet},
    time::{sleep, timeout},
};

use super::{Bootstrap, LaunchConfig, VERSION, filesystem::connect_peer, record_id, wire_json};

const INSTALLATION: &str = "x-app-installation";
const GENERATION: &str = "x-app-generation";
const DELEGATION: &str = "x-app-delegation";
const IDEMPOTENCY: &str = "idempotency-key";
const EVENT_CURSOR: &str = "last-event-id";
const TRUSTED_APP_ID: &str = "x-rentnerproxy-app-id";
const TRUSTED_APP_UID: &str = "x-rentnerproxy-app-uid";
const MAX_JSON_BYTES: usize = 1_048_576;
const MAX_HEADER_BYTES: usize = 16_384;
const MAX_HEADERS: usize = 32;
const MAX_CONNECTIONS: usize = 32;
const HEADER_TIMEOUT: Duration = Duration::from_secs(5);
const RPC_TIMEOUT: Duration = Duration::from_secs(10);
const STREAM_TIMEOUT: Duration = Duration::from_secs(300);

pub(super) struct Generation {
    uid: u32,
    uid_header: HeaderValue,
    app_id: HeaderValue,
    installation: HeaderValue,
    generation: HeaderValue,
    verifier: digest::Digest,
    gateway_socket: PathBuf,
    gateway_uid: u32,
    bridge_auth: HeaderValue,
    lease_identity: Bytes,
}

impl Generation {
    pub(super) fn new(
        config: &LaunchConfig,
        verifier: digest::Digest,
        gateway_socket: PathBuf,
        gateway_uid: u32,
        bridge_auth: HeaderValue,
    ) -> io::Result<Self> {
        Ok(Self {
            uid: config.uid,
            uid_header: identity_header(&config.uid.to_string())?,
            app_id: identity_header(&config.app_id)?,
            installation: identity_header(&config.installation_id)?,
            generation: identity_header(&config.generation.to_string())?,
            verifier,
            gateway_socket,
            gateway_uid,
            bridge_auth,
            lease_identity: Bytes::from(
                json!({
                    "identity": {
                        "appId": config.app_id,
                        "installationId": config.installation_id,
                        "generation": config.generation,
                        "uid": config.uid,
                    }
                })
                .to_string(),
            ),
        })
    }

    pub(super) async fn lease_expires_at(&self) -> io::Result<Option<u64>> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Lease {
            expires_at: u64,
        }

        let unavailable = || io::Error::other("App lease authority unavailable");
        let request = Request::post("/internal/v1/app-generations/lease")
            .header(header::HOST, "localhost")
            .header(header::CONNECTION, "close")
            .header(header::AUTHORIZATION, &self.bridge_auth)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(self.lease_identity.clone()))
            .map_err(|_| unavailable())?;
        let (response, _connection) =
            send_to_peer(&self.gateway_socket, self.gateway_uid, request).await?;
        match response.status() {
            StatusCode::UNAUTHORIZED => Ok(None),
            StatusCode::OK => {
                let body = Limited::new(response.into_body(), 4096)
                    .collect()
                    .await
                    .map_err(|_| unavailable())?
                    .to_bytes();
                let lease: Lease = serde_json::from_slice(&body).map_err(|_| unavailable())?;
                Ok(Some(lease.expires_at))
            }
            _ => Err(unavailable()),
        }
    }

    fn authorize(&self, peer: Option<u32>, headers: &HeaderMap) -> Result<(), Problem> {
        if peer != Some(self.uid) {
            return Err(Problem::Identity);
        }
        let credential = unique_header(headers, header::AUTHORIZATION.as_str())
            .map_err(|_| Problem::Credential)?
            .and_then(|value| value.as_bytes().strip_prefix(b"Bearer "))
            .ok_or(Problem::Credential)?;
        let candidate = digest::digest(&digest::SHA256, credential);
        constant_time::verify_slices_are_equal(self.verifier.as_ref(), candidate.as_ref())
            .map_err(|_| Problem::Credential)?;
        if unique_header(headers, INSTALLATION)? != Some(&self.installation)
            || unique_header(headers, GENERATION)? != Some(&self.generation)
        {
            return Err(Problem::Identity);
        }
        Ok(())
    }
}

pub(super) async fn serve(listener: UnixListener, generation: Arc<Generation>) -> io::Result<()> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = connections.join_next(), if !connections.is_empty() => {},
            accepted = listener.accept(), if connections.len() < MAX_CONNECTIONS => {
                let (stream, _) = accepted?;
                let peer = stream.peer_cred().ok().map(|credential| credential.uid());
                let generation = Arc::clone(&generation);
                connections.spawn(async move {
                    let service = service_fn(move |request| {
                        let generation = Arc::clone(&generation);
                        async move {
                            let response = match timeout(RPC_TIMEOUT, forward(&generation, peer, request)).await {
                                Ok(Ok(response)) => response,
                                Ok(Err(problem)) => problem.response(),
                                Err(_) => Problem::Deadline.response(),
                            };
                            Ok::<_, Infallible>(response)
                        }
                    });
                    let connection = server::conn::http1::Builder::new()
                        .timer(TokioTimer::new())
                        .header_read_timeout(HEADER_TIMEOUT)
                        .max_headers(MAX_HEADERS)
                        .max_buf_size(MAX_HEADER_BYTES)
                        .serve_connection(TokioIo::new(stream), service);
                    let _ = timeout(STREAM_TIMEOUT, connection).await;
                });
            }
        }
    }
}

#[derive(Clone, Copy)]
struct Operation {
    json: bool,
    events: bool,
}

static APP_OPERATIONS: LazyLock<[HttpDescriptor; 12]> = LazyLock::new(|| {
    [
        HttpOperation::GetPlatformContext,
        HttpOperation::SubscribeToEvents,
        HttpOperation::CheckAuthorization,
        HttpOperation::ListProxyHosts,
        HttpOperation::UpdateOwnedProxyHost,
        HttpOperation::ProbeUpstream,
        HttpOperation::PublishNotification,
        HttpOperation::RecordAuditEvent,
        HttpOperation::ReadSecret,
        HttpOperation::GetProvider,
        HttpOperation::GetOperation,
        HttpOperation::CancelOperation,
    ]
    .map(HttpOperation::descriptor)
});

fn operation(request: &Request<Incoming>) -> Result<Operation, Problem> {
    let uri = request.uri();
    if request.version() != Version::HTTP_11
        || uri.scheme().is_some()
        || uri.authority().is_some()
        || uri.query().is_some()
    {
        return Err(Problem::Request);
    }
    let method = match *request.method() {
        Method::GET => HttpMethod::Get,
        Method::POST => HttpMethod::Post,
        _ => return Err(Problem::Route),
    };
    let descriptor = APP_OPERATIONS
        .iter()
        .find(|operation| operation.method == method && route_matches(operation, uri.path()))
        .ok_or(Problem::Route)?;
    Ok(Operation {
        json: descriptor.request.is_some(),
        events: descriptor.event.is_some(),
    })
}

fn route_matches(operation: &HttpDescriptor, path: &str) -> bool {
    if operation.path_parameter.is_none() {
        return path == operation.path;
    }
    let Some((prefix, parameter)) = operation.path.split_once('{') else {
        return false;
    };
    let Some((_, suffix)) = parameter.split_once('}') else {
        return false;
    };
    path.strip_prefix(prefix)
        .and_then(|id| id.strip_suffix(suffix))
        .is_some_and(record_id)
}

async fn forward(
    generation: &Generation,
    peer: Option<u32>,
    request: Request<Incoming>,
) -> Result<Response<Body>, Problem> {
    generation.authorize(peer, request.headers())?;
    let operation = operation(&request)?;
    let (parts, body) = request.into_parts();
    let content_type = unique_header(&parts.headers, header::CONTENT_TYPE.as_str())?;
    if operation.json && !content_type.is_some_and(|value| media_type(value, "application/json")) {
        return Err(Problem::MediaType);
    }
    let body = collect(body).await?;
    if (operation.json && !wire_json::valid(&body)) || (!operation.json && !body.is_empty()) {
        return Err(Problem::Request);
    }
    let mut outgoing = Request::builder()
        .method(parts.method)
        .uri(parts.uri)
        .header(header::HOST, "localhost")
        .header(header::CONNECTION, "close")
        .header(header::AUTHORIZATION, &generation.bridge_auth)
        .header(INSTALLATION, &generation.installation)
        .header(GENERATION, &generation.generation)
        .header(TRUSTED_APP_ID, &generation.app_id)
        .header(TRUSTED_APP_UID, &generation.uid_header);
    for name in [
        DELEGATION,
        IDEMPOTENCY,
        EVENT_CURSOR,
        header::CONTENT_TYPE.as_str(),
    ] {
        if let Some(value) = unique_header(&parts.headers, name)? {
            outgoing = outgoing.header(name, value);
        }
    }
    let outgoing = outgoing
        .body(Full::new(body))
        .map_err(|_| Problem::Request)?;
    let (response, connection) =
        send_to_peer(&generation.gateway_socket, generation.gateway_uid, outgoing)
            .await
            .map_err(|_| Problem::Unavailable)?;
    let (parts, incoming) = response.into_parts();
    let content_type = unique_header(&parts.headers, header::CONTENT_TYPE.as_str())
        .map_err(|_| Problem::Unavailable)?;
    let mut response = Response::builder()
        .status(parts.status)
        .header(header::CACHE_CONTROL, "no-store");
    if let Some(value) = content_type {
        response = response.header(header::CONTENT_TYPE, value);
    }
    let body = if operation.events
        && parts.status == StatusCode::OK
        && content_type.is_some_and(|value| media_type(value, "text/event-stream"))
    {
        Body::new(EventStream {
            incoming,
            _connection: connection,
        })
    } else {
        let body = collect(incoming).await.map_err(|_| Problem::Unavailable)?;
        Body::from(body)
    };
    response.body(body).map_err(|_| Problem::Unavailable)
}

struct EventStream {
    incoming: Incoming,
    _connection: PeerConnection,
}

impl HttpBody for EventStream {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        match std::task::ready!(Pin::new(&mut self.incoming).poll_frame(context)) {
            Some(Ok(frame)) if frame.is_trailers() => Poll::Ready(None),
            frame => Poll::Ready(frame),
        }
    }
}

fn unique_header<'a>(
    headers: &'a HeaderMap,
    name: &str,
) -> Result<Option<&'a HeaderValue>, Problem> {
    let mut values = headers.get_all(name).into_iter();
    let value = values.next();
    if values.next().is_some() {
        return Err(Problem::Request);
    }
    Ok(value)
}

fn identity_header(value: &str) -> io::Result<HeaderValue> {
    HeaderValue::from_str(value).map_err(|_| io::Error::other("Invalid app transport identity"))
}

fn media_type(value: &HeaderValue, expected: &str) -> bool {
    value.to_str().is_ok_and(|value| {
        value
            .split(';')
            .next()
            .is_some_and(|kind| kind.trim().eq_ignore_ascii_case(expected))
    })
}

async fn collect(body: Incoming) -> Result<Bytes, Problem> {
    Limited::new(body, MAX_JSON_BYTES)
        .collect()
        .await
        .map(|collected| collected.to_bytes())
        .map_err(|error| {
            if error.is::<LengthLimitError>() {
                Problem::Size
            } else {
                Problem::Request
            }
        })
}

struct PeerConnection(JoinHandle<()>);

impl Drop for PeerConnection {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn send_to_peer(
    socket: &Path,
    uid: u32,
    request: Request<Full<Bytes>>,
) -> io::Result<(Response<Incoming>, PeerConnection)> {
    let stream = connect_peer(socket, uid).await?;
    let unavailable = |_| io::Error::other("Unix HTTP peer unavailable");
    let (mut sender, connection) = client::conn::http1::Builder::new()
        .max_buf_size(MAX_HEADER_BYTES)
        .max_headers(MAX_HEADERS)
        .handshake(TokioIo::new(stream))
        .await
        .map_err(unavailable)?;
    let connection = PeerConnection(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let response = sender.send_request(request).await.map_err(unavailable)?;
    Ok((response, connection))
}

#[derive(Deserialize)]
struct AppHealth {
    healthy: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AppReady {
    ready: bool,
    protocol_version: String,
    providers: Vec<serde::de::IgnoredAny>,
}

pub(super) async fn app_ready(bootstrap: &Bootstrap<'_>, uid: u32) -> io::Result<()> {
    loop {
        if let Ok(Ok(())) = timeout(RPC_TIMEOUT, check_app_ready(bootstrap, uid)).await {
            return Ok(());
        }
        sleep(Duration::from_millis(200)).await;
    }
}

async fn check_app_ready(bootstrap: &Bootstrap<'_>, uid: u32) -> io::Result<()> {
    let healthy: AppHealth = probe_app(bootstrap, uid, "/app/v1/health").await?;
    let ready: AppReady = probe_app(bootstrap, uid, "/app/v1/ready").await?;
    if !healthy.healthy
        || !ready.ready
        || ready.protocol_version != VERSION
        || ready.providers.len() > 32
    {
        return Err(io::Error::other(
            "App has not reported compatible readiness",
        ));
    }
    Ok(())
}

async fn probe_app<T: DeserializeOwned>(
    bootstrap: &Bootstrap<'_>,
    uid: u32,
    uri: &'static str,
) -> io::Result<T> {
    let error = || io::Error::other("Invalid app readiness response");
    let request = Request::builder()
        .uri(uri)
        .header(header::HOST, "localhost")
        .header(header::CONNECTION, "close")
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", bootstrap.app_credential),
        )
        .header(INSTALLATION, bootstrap.installation_id)
        .header(GENERATION, bootstrap.generation.to_string())
        .body(Full::new(Bytes::new()))
        .map_err(|_| error())?;
    let (response, _connection) = send_to_peer(bootstrap.app_socket, uid, request).await?;
    if response.status() != StatusCode::OK {
        return Err(error());
    }
    let body = collect(response.into_body()).await.map_err(|_| error())?;
    if !wire_json::valid(&body) {
        return Err(error());
    }
    serde_json::from_slice(&body).map_err(|_| error())
}

#[derive(Clone, Copy, Debug)]
enum Problem {
    Credential,
    Identity,
    Request,
    Route,
    Size,
    MediaType,
    Deadline,
    Unavailable,
}

impl Problem {
    fn response(self) -> Response<Body> {
        let (status, code) = match self {
            Self::Credential => (StatusCode::UNAUTHORIZED, "appCredentialRejected"),
            Self::Identity => (StatusCode::FORBIDDEN, "installationContextRejected"),
            Self::Request => (StatusCode::BAD_REQUEST, "invalidRequest"),
            Self::Route => (StatusCode::NOT_FOUND, "operationNotFound"),
            Self::Size => (StatusCode::PAYLOAD_TOO_LARGE, "payloadTooLarge"),
            Self::MediaType => (StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupportedMediaType"),
            Self::Deadline => (StatusCode::GATEWAY_TIMEOUT, "deadlineExceeded"),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "platformUnavailable"),
        };
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let request_id = format!(
            "ipc-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        );
        let body = json!({
            "type": format!("urn:rentnerproxy:problem:{code}"),
            "title": status.canonical_reason().unwrap_or("App IPC request failed"),
            "status": status.as_u16(),
            "code": code,
            "requestId": request_id,
        });
        let mut response = Response::new(Body::from(body.to_string()));
        *response.status_mut() = status;
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        );
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
    }
}
