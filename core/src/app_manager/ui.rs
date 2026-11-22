mod package;

use std::{
    collections::BTreeMap,
    fs::{self, DirBuilder, Permissions},
    io,
    os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt, chown},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::body::Body;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    Method, Request, Response, StatusCode, Version,
    body::Incoming,
    header::{self, HeaderMap, HeaderValue},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde::Serialize;
use serde_json::Value;
use tokio::{net::UnixListener, sync::Semaphore, task::JoinSet, time::timeout};
use tokio_util::sync::CancellationToken;

use super::{catalog, lifecycle};
use crate::app_ipc::{
    APP_ROOT, WEB_UID,
    filesystem::require_safe_parents,
    gateway::{
        APP_API_PREFIX, HEADER_TIMEOUT, MAX_HEADER_BYTES, MAX_HEADERS, MAX_JSON_BYTES, RPC_TIMEOUT,
        UI_LEASE, send_to_peer,
    },
    wire_json,
};

use super::{MAX_GENERATION, bad, valid_id};
pub(super) use package::Package;

const SOCKET: &str = "/run/rentnerproxy/app-ui/web.sock";
const MAX_CONNECTIONS: usize = 16;
const MAX_LIST_PROBES: usize = 16;
const MAX_LIST_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_CATALOG_RESPONSE_BYTES: usize = 12 * 1024 * 1024;
const MAX_INSTALL_BYTES: usize = 4 * 1024;
const MAX_OPERATIONS_PER_INSTALLATION: usize = 4;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(20);

#[cfg(test)]
#[path = "../../tests/private/app_ui.rs"]
pub(super) mod tests;

#[derive(Clone, Default)]
pub(super) struct Registry {
    entries: Arc<Mutex<BTreeMap<String, Arc<Entry>>>>,
}

struct Entry {
    package: Package,
    broker_socket: PathBuf,
    cancelled: CancellationToken,
    operations: Semaphore,
}

pub(super) struct Publication {
    registry: Registry,
    entry: Arc<Entry>,
}

impl Registry {
    pub(super) fn publish(&self, package: Package) -> Option<Publication> {
        self.publish_in(package, Path::new(APP_ROOT))
    }

    fn publish_in(&self, package: Package, app_root: &Path) -> Option<Publication> {
        let broker_socket = app_root
            .join(package.metadata.uid.to_string())
            .join(package.metadata.generation.to_string())
            .join("core.sock");
        let entry = Arc::new(Entry {
            package,
            broker_socket,
            cancelled: CancellationToken::new(),
            operations: Semaphore::new(MAX_OPERATIONS_PER_INSTALLATION),
        });
        let key = entry.package.metadata.installation_id.clone();
        if let Some(previous) = self.entries.lock().ok()?.insert(key, Arc::clone(&entry)) {
            previous.cancelled.cancel();
        }
        Some(Publication {
            registry: self.clone(),
            entry,
        })
    }

    fn entry(&self, id: &str, generation: u64) -> Result<Arc<Entry>, StatusCode> {
        let entries = self
            .entries
            .lock()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let entry = entries.get(id).ok_or(StatusCode::NOT_FOUND)?;
        if entry.package.metadata.generation != generation || entry.cancelled.is_cancelled() {
            return Err(StatusCode::PRECONDITION_FAILED);
        }
        Ok(Arc::clone(entry))
    }

    fn snapshot(&self) -> Result<Vec<Arc<Entry>>, StatusCode> {
        let entries = self
            .entries
            .lock()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        Ok(entries.values().cloned().collect())
    }
}

impl Drop for Publication {
    fn drop(&mut self) {
        self.entry.cancelled.cancel();
        if let Ok(mut entries) = self.registry.entries.lock() {
            let id = &self.entry.package.metadata.installation_id;
            if entries
                .get(id)
                .is_some_and(|entry| Arc::ptr_eq(entry, &self.entry))
            {
                entries.remove(id);
            }
        }
    }
}

pub(super) fn bind() -> io::Result<UnixListener> {
    bind_path(Path::new(SOCKET))
}

fn bind_path(path: &Path) -> io::Result<UnixListener> {
    require_safe_parents(path.parent().expect("socket directory"), 0)?;
    let parent = path.parent().expect("socket directory");
    match DirBuilder::new().mode(0o700).create(parent) {
        Ok(()) => {
            chown(parent, Some(0), Some(WEB_UID))?;
            fs::set_permissions(parent, Permissions::from_mode(0o710))?;
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.gid() != WEB_UID
        || metadata.mode() & 0o7777 != 0o710
    {
        return Err(bad("Unsafe app UI socket directory"));
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() && metadata.uid() == 0 => {
            fs::remove_file(path)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
        _ => return Err(bad("Unsafe app UI socket")),
    }
    let listener = UnixListener::bind(path)?;
    chown(path, Some(0), Some(WEB_UID))?;
    fs::set_permissions(path, Permissions::from_mode(0o660))?;
    Ok(listener)
}

pub(super) async fn serve(
    listener: UnixListener,
    registry: Registry,
    catalog: catalog::Endpoint,
) -> io::Result<()> {
    let mut connections = JoinSet::new();
    let blocking = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        tokio::select! {
            _ = connections.join_next(), if !connections.is_empty() => {}
            accepted = listener.accept(), if connections.len() < MAX_CONNECTIONS => {
                let (stream, _) = accepted?;
                if !stream.peer_cred().is_ok_and(|peer| peer.uid() == WEB_UID) {
                    continue;
                }
                let registry = registry.clone();
                let catalog = catalog.clone();
                let blocking = Arc::clone(&blocking);
                connections.spawn(async move {
                    let service = service_fn(move |request| {
                        let registry = registry.clone();
                        let catalog = catalog.clone();
                        let blocking = Arc::clone(&blocking);
                        async move {
                            let response = timeout(RPC_TIMEOUT, handle(registry, catalog, blocking, request))
                                .await
                                .unwrap_or(Err(StatusCode::GATEWAY_TIMEOUT))
                                .unwrap_or_else(empty);
                            Ok::<_, std::convert::Infallible>(response)
                        }
                    });
                    let connection = http1::Builder::new()
                        .timer(TokioTimer::new())
                        .header_read_timeout(HEADER_TIMEOUT)
                        .max_headers(MAX_HEADERS)
                        .max_buf_size(MAX_HEADER_BYTES)
                        .keep_alive(false)
                        .serve_connection(TokioIo::new(stream), service);
                    let _ = timeout(CONNECTION_TIMEOUT, connection).await;
                });
            }
        }
    }
}

async fn handle(
    registry: Registry,
    catalog: catalog::Endpoint,
    blocking: Arc<Semaphore>,
    request: Request<Incoming>,
) -> Result<Response<Body>, StatusCode> {
    let uri = request.uri();
    if request.version() != Version::HTTP_11
        || uri.scheme().is_some()
        || uri.authority().is_some()
        || uri.query().is_some()
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let (parts, incoming) = request.into_parts();
    let path = parts.uri.path();
    if parts.method == Method::GET {
        if !read_body(incoming).await?.is_empty() {
            return Err(StatusCode::BAD_REQUEST);
        }
        if path == "/v1/apps" {
            return list(&registry).await;
        }
        if path == "/v1/catalog" {
            let view = catalog
                .view()
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
            if view.len() > MAX_CATALOG_RESPONSE_BYTES {
                return Err(StatusCode::PAYLOAD_TOO_LARGE);
            }
            return response("application/json", Bytes::from(view));
        }
        let (entry, resource, value) = selection(&registry, path)?;
        return protected(&entry, async {
            entry.check_live().await?;
            match (resource, value) {
                ("metadata", None) => json(&entry.package.metadata, MAX_JSON_BYTES),
                ("assets", Some(value)) if package::valid_relative_path(value) => {
                    let permit = blocking
                        .try_acquire_owned()
                        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                    let directory = Arc::clone(&entry);
                    let value = value.to_owned();
                    let bytes = tokio::task::spawn_blocking(move || {
                        let _permit = permit;
                        directory.package.asset(&value)
                    })
                    .await
                    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
                    .map_err(|_| StatusCode::NOT_FOUND)?;
                    entry.check_live().await?;
                    response("application/octet-stream", bytes)
                }
                ("operations", Some(value)) if valid_id(value) => {
                    let operation = entry
                        .package
                        .operations
                        .get(value)
                        .ok_or(StatusCode::NOT_FOUND)?;
                    json(&operation.access, MAX_JSON_BYTES)
                }
                _ => Err(StatusCode::NOT_FOUND),
            }
        })
        .await;
    }
    if parts.method != Method::POST {
        return Err(StatusCode::NOT_FOUND);
    }
    if matches!(path, "/v1/catalog/install" | "/v1/catalog/lifecycle") {
        if !header_value(&parts.headers, header::CONTENT_TYPE.as_str()).is_some_and(json_media_type)
        {
            return Err(StatusCode::BAD_REQUEST);
        }
        let bytes = read_body_limited(incoming, MAX_INSTALL_BYTES).await?;
        let map_failure = |error| match error {
            catalog::Failure::Conflict => StatusCode::CONFLICT,
            _ => StatusCode::SERVICE_UNAVAILABLE,
        };
        let mut reply = if path == "/v1/catalog/install" {
            let selection = serde_json::from_slice(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
            let install = catalog.submit(selection).map_err(map_failure)?;
            json(&install, MAX_INSTALL_BYTES)?
        } else {
            let request: lifecycle::Request =
                serde_json::from_slice(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
            if !request.valid() {
                return Err(StatusCode::BAD_REQUEST);
            }
            let operation = catalog.submit_lifecycle(request).map_err(map_failure)?;
            json(&operation, MAX_INSTALL_BYTES)?
        };
        *reply.status_mut() = StatusCode::ACCEPTED;
        return Ok(reply);
    }
    let (entry, "operations", Some(id)) = selection(&registry, path)? else {
        return Err(StatusCode::NOT_FOUND);
    };
    if !valid_id(id) {
        return Err(StatusCode::NOT_FOUND);
    }
    let idempotency = header_value(&parts.headers, "idempotency-key")
        .filter(|value| value.to_str().is_ok_and(valid_id))
        .ok_or(StatusCode::BAD_REQUEST)?;
    if !header_value(&parts.headers, header::CONTENT_TYPE.as_str()).is_some_and(json_media_type) {
        return Err(StatusCode::BAD_REQUEST);
    }
    protected(&entry, entry.invoke(id, idempotency, incoming)).await
}

fn selection<'a>(
    registry: &Registry,
    path: &'a str,
) -> Result<(Arc<Entry>, &'a str, Option<&'a str>), StatusCode> {
    let mut components = path
        .strip_prefix("/v1/apps/")
        .ok_or(StatusCode::NOT_FOUND)?
        .splitn(4, '/');
    let id = components
        .next()
        .filter(|id| valid_id(id))
        .ok_or(StatusCode::NOT_FOUND)?;
    let generation = components
        .next()
        .and_then(generation_number)
        .ok_or(StatusCode::NOT_FOUND)?;
    let resource = components.next().ok_or(StatusCode::NOT_FOUND)?;
    Ok((registry.entry(id, generation)?, resource, components.next()))
}

fn generation_number(value: &str) -> Option<u64> {
    if value.starts_with('0') || value.len() > 16 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    value
        .parse()
        .ok()
        .filter(|n| (1..=MAX_GENERATION).contains(n))
}

async fn protected<T>(
    entry: &Entry,
    work: impl Future<Output = Result<T, StatusCode>>,
) -> Result<T, StatusCode> {
    tokio::select! {
        biased;
        _ = entry.cancelled.cancelled() => Err(StatusCode::PRECONDITION_FAILED),
        result = work => result,
    }
}

async fn list(registry: &Registry) -> Result<Response<Body>, StatusCode> {
    let entries = registry.snapshot()?;
    let mut live = Vec::new();
    for batch in entries.chunks(MAX_LIST_PROBES) {
        let mut tasks = JoinSet::new();
        for entry in batch {
            let entry = Arc::clone(entry);
            tasks.spawn(async move {
                protected(&entry, entry.check_live())
                    .await
                    .ok()
                    .map(|()| entry)
            });
        }
        while let Some(result) = tasks.join_next().await {
            if let Ok(Some(entry)) = result {
                live.push(entry);
            }
        }
    }
    live.sort_unstable_by(|first, second| {
        first
            .package
            .metadata
            .installation_id
            .cmp(&second.package.metadata.installation_id)
    });
    let metadata: Vec<_> = live
        .iter()
        .filter(|entry| !entry.cancelled.is_cancelled())
        .map(|entry| &entry.package.metadata)
        .collect();
    json(&metadata, MAX_LIST_RESPONSE_BYTES)
}

impl Entry {
    fn broker_request(&self) -> hyper::http::request::Builder {
        Request::builder()
            .header(header::HOST, "localhost")
            .header(header::CONNECTION, "close")
            .header("x-app-installation", &self.package.metadata.installation_id)
            .header(
                "x-app-generation",
                self.package.metadata.generation.to_string(),
            )
    }

    async fn check_live(&self) -> Result<(), StatusCode> {
        let request = self
            .broker_request()
            .uri(UI_LEASE)
            .body(Full::new(Bytes::new()))
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let (response, _) = timeout(
            Duration::from_secs(3),
            send_to_peer(&self.broker_socket, 0, request),
        )
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .map_err(socket_status)?;
        match response.status() {
            StatusCode::NO_CONTENT => Ok(()),
            StatusCode::FORBIDDEN => Err(StatusCode::PRECONDITION_FAILED),
            _ => Err(StatusCode::SERVICE_UNAVAILABLE),
        }
    }

    async fn invoke(
        &self,
        id: &str,
        idempotency: &HeaderValue,
        incoming: Incoming,
    ) -> Result<Response<Body>, StatusCode> {
        let operation = self
            .package
            .operations
            .get(id)
            .ok_or(StatusCode::NOT_FOUND)?;
        let _permit = self
            .operations
            .try_acquire()
            .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
        let body = read_body(incoming).await?;
        let payload = json_object(&body).ok_or(StatusCode::BAD_REQUEST)?;
        if !operation.access.valid_resource(&payload) || !operation.request.is_valid(&payload) {
            return Err(StatusCode::BAD_REQUEST);
        }
        let request = self
            .broker_request()
            .method(Method::POST)
            .uri(format!("{APP_API_PREFIX}{id}"))
            .header(header::CONTENT_TYPE, "application/json")
            .header("idempotency-key", idempotency)
            .body(Full::new(body))
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let (reply, _connection) = send_to_peer(&self.broker_socket, 0, request)
            .await
            .map_err(socket_status)?;
        match reply.status() {
            StatusCode::FORBIDDEN => return Err(StatusCode::PRECONDITION_FAILED),
            StatusCode::CONFLICT => return Err(StatusCode::CONFLICT),
            StatusCode::GATEWAY_TIMEOUT => return Err(StatusCode::GATEWAY_TIMEOUT),
            StatusCode::OK => {}
            _ => return Err(StatusCode::BAD_GATEWAY),
        }
        if !header_value(reply.headers(), header::CONTENT_TYPE.as_str())
            .is_some_and(json_media_type)
        {
            return Err(StatusCode::BAD_GATEWAY);
        }
        let body = read_body(reply.into_body())
            .await
            .map_err(|_| StatusCode::BAD_GATEWAY)?;
        let payload = json_object(&body).ok_or(StatusCode::BAD_GATEWAY)?;
        if !operation.response.is_valid(&payload) {
            return Err(StatusCode::BAD_GATEWAY);
        }
        response("application/json", body)
    }
}

fn socket_status(error: io::Error) -> StatusCode {
    match error.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => {
            StatusCode::PRECONDITION_FAILED
        }
        _ => StatusCode::SERVICE_UNAVAILABLE,
    }
}

fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a HeaderValue> {
    let mut values = headers.get_all(name).into_iter();
    values.next().filter(|_| values.next().is_none())
}

fn json_media_type(value: &HeaderValue) -> bool {
    value.to_str().is_ok_and(|value| {
        value
            .split(';')
            .next()
            .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"))
    })
}

fn json_object(body: &[u8]) -> Option<Value> {
    if !wire_json::valid(body) {
        return None;
    }
    let payload: Value = serde_json::from_slice(body).ok()?;
    (payload.is_object() && bounded_lists(&payload)).then_some(payload)
}

fn bounded_lists(value: &Value) -> bool {
    match value {
        Value::Array(items) => items.len() <= 100 && items.iter().all(bounded_lists),
        Value::Object(fields) => fields.values().all(bounded_lists),
        _ => true,
    }
}

async fn read_body(incoming: Incoming) -> Result<Bytes, StatusCode> {
    read_body_limited(incoming, MAX_JSON_BYTES).await
}

async fn read_body_limited(incoming: Incoming, limit: usize) -> Result<Bytes, StatusCode> {
    Limited::new(incoming, limit)
        .collect()
        .await
        .map(|collected| collected.to_bytes())
        .map_err(|error| {
            if error.is::<http_body_util::LengthLimitError>() {
                StatusCode::PAYLOAD_TOO_LARGE
            } else {
                StatusCode::BAD_REQUEST
            }
        })
}

fn json(value: &impl Serialize, limit: usize) -> Result<Response<Body>, StatusCode> {
    let bytes = serde_json::to_vec(value).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if bytes.len() > limit {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    response("application/json", bytes)
}

fn response(
    content_type: &'static str,
    body: impl Into<Body>,
) -> Result<Response<Body>, StatusCode> {
    Response::builder()
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, "no-store")
        .body(body.into())
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
}

fn empty(status: StatusCode) -> Response<Body> {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
