use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use axum::body::Body;
use bytes::Bytes;
use http_body_util::Full;
use hyper::{
    Method, Request, Response, StatusCode,
    header::{self, HeaderValue},
};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use super::{header_value, json_media_type, read_body_limited, response, socket_status};
use crate::app_ipc::{
    APP_ROOT,
    gateway::{APP_PROVIDER_PREFIX, MAX_JSON_BYTES, send_to_peer},
};

pub(super) const MAX_CALLS_PER_INSTALLATION: usize = 4;

/// The live generation of each installation whose manifest declares providers.
#[derive(Clone, Default)]
pub(super) struct Registry {
    endpoints: Arc<Mutex<BTreeMap<String, Arc<Endpoint>>>>,
}

pub(super) struct Endpoint {
    installation_id: String,
    generation: u64,
    pub(super) broker_socket: PathBuf,
    cancelled: CancellationToken,
    pub(super) calls: Semaphore,
}

/// Withdraws the endpoint when its generation stops or a newer one replaces it.
pub(in crate::app_manager) struct Publication {
    registry: Registry,
    pub(super) endpoint: Arc<Endpoint>,
}

impl Registry {
    pub(super) fn publish(
        &self,
        installation_id: &str,
        uid: u32,
        generation: u64,
    ) -> Option<Publication> {
        self.publish_in(installation_id, uid, generation, Path::new(APP_ROOT))
    }

    pub(super) fn publish_in(
        &self,
        installation_id: &str,
        uid: u32,
        generation: u64,
        app_root: &Path,
    ) -> Option<Publication> {
        let endpoint = Arc::new(Endpoint {
            installation_id: installation_id.to_owned(),
            generation,
            broker_socket: app_root
                .join(uid.to_string())
                .join(generation.to_string())
                .join("core.sock"),
            cancelled: CancellationToken::new(),
            calls: Semaphore::new(MAX_CALLS_PER_INSTALLATION),
        });
        if let Some(previous) = self
            .endpoints
            .lock()
            .ok()?
            .insert(installation_id.to_owned(), Arc::clone(&endpoint))
        {
            previous.cancelled.cancel();
        }
        Some(Publication {
            registry: self.clone(),
            endpoint,
        })
    }

    /// Invoke a provider of the installation's live generation. Its broker checks the
    /// registration, the grant and the contract, so a replaced generation answers 412.
    /// With an expected generation, any other live generation answers 412 as well, so a
    /// caller never receives an answer of a generation it did not authorize.
    pub(super) async fn invoke(
        &self,
        installation_id: &str,
        provider_id: &str,
        expected_generation: Option<u64>,
        idempotency: &HeaderValue,
        body: Bytes,
    ) -> Result<Response<Body>, StatusCode> {
        let endpoint = self
            .endpoints
            .lock()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
            .get(installation_id)
            .cloned()
            .ok_or(StatusCode::NOT_FOUND)?;
        // The endpoint was selected under the lock; a later replacement cancels it below.
        if expected_generation.is_some_and(|generation| generation != endpoint.generation) {
            return Err(StatusCode::PRECONDITION_FAILED);
        }
        let _permit = endpoint
            .calls
            .try_acquire()
            .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
        tokio::select! {
            biased;
            () = endpoint.cancelled.cancelled() => Err(StatusCode::PRECONDITION_FAILED),
            result = endpoint.call(provider_id, idempotency, body) => result,
        }
    }
}

impl Endpoint {
    async fn call(
        &self,
        provider_id: &str,
        idempotency: &HeaderValue,
        body: Bytes,
    ) -> Result<Response<Body>, StatusCode> {
        let request = Request::builder()
            .method(Method::POST)
            .uri(format!("{APP_PROVIDER_PREFIX}{provider_id}"))
            .header(header::HOST, "localhost")
            .header(header::CONNECTION, "close")
            .header("x-app-installation", &self.installation_id)
            .header("x-app-generation", self.generation.to_string())
            .header(header::CONTENT_TYPE, "application/json")
            .header("idempotency-key", idempotency)
            .body(Full::new(body))
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let (reply, _connection) = send_to_peer(&self.broker_socket, 0, request)
            .await
            .map_err(socket_status)?;
        match reply.status() {
            StatusCode::OK => {}
            StatusCode::NOT_FOUND => return Err(StatusCode::NOT_FOUND),
            StatusCode::BAD_REQUEST
            | StatusCode::UNSUPPORTED_MEDIA_TYPE
            | StatusCode::PAYLOAD_TOO_LARGE => return Err(StatusCode::BAD_REQUEST),
            StatusCode::CONFLICT => return Err(StatusCode::CONFLICT),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                return Err(StatusCode::PRECONDITION_FAILED);
            }
            StatusCode::GATEWAY_TIMEOUT => return Err(StatusCode::GATEWAY_TIMEOUT),
            _ => return Err(StatusCode::SERVICE_UNAVAILABLE),
        }
        if !header_value(reply.headers(), header::CONTENT_TYPE.as_str())
            .is_some_and(json_media_type)
        {
            return Err(StatusCode::BAD_GATEWAY);
        }
        let result = read_body_limited(reply.into_body(), MAX_JSON_BYTES)
            .await
            .map_err(|_| StatusCode::BAD_GATEWAY)?;
        response("application/json", result)
    }
}

impl Drop for Publication {
    fn drop(&mut self) {
        self.endpoint.cancelled.cancel();
        if let Ok(mut endpoints) = self.registry.endpoints.lock() {
            let id = &self.endpoint.installation_id;
            if endpoints
                .get(id)
                .is_some_and(|endpoint| Arc::ptr_eq(endpoint, &self.endpoint))
            {
                endpoints.remove(id);
            }
        }
    }
}
