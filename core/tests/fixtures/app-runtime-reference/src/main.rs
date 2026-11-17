mod providers;

use axum::{
    Json, Router,
    extract::{ConnectInfo, DefaultBodyLimit, Request, State, connect_info::Connected},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    serve::IncomingStream,
};
use providers::{ProviderRequest, Providers};
use serde_json::json;
use std::{
    env, fs, io,
    os::unix::fs::PermissionsExt,
    sync::{Arc, Mutex},
};
use tokio::net::UnixListener;

#[derive(Clone)]
struct PeerUid(Option<u32>);

impl Connected<IncomingStream<'_, UnixListener>> for PeerUid {
    fn connect_info(stream: IncomingStream<'_, UnixListener>) -> Self {
        Self(
            stream
                .io()
                .peer_cred()
                .ok()
                .map(|credential| credential.uid()),
        )
    }
}

struct Installation {
    id: String,
    generation: String,
    broker_uid: u32,
    providers: Mutex<Providers>,
}

async fn authorize(
    State(installation): State<Arc<Installation>>,
    ConnectInfo(peer): ConnectInfo<PeerUid>,
    request: Request,
    next: Next,
) -> Response {
    let headers = request.headers();
    if peer.0 != Some(installation.broker_uid)
        || headers
            .get("x-app-installation")
            .and_then(|value| value.to_str().ok())
            != Some(installation.id.as_str())
        || headers
            .get("x-app-generation")
            .and_then(|value| value.to_str().ok())
            != Some(installation.generation.as_str())
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "installationContextRejected" })),
        )
            .into_response();
    }
    next.run(request).await
}

async fn probe(
    State(installation): State<Arc<Installation>>,
    Json(request): Json<ProviderRequest>,
) -> Response {
    let Ok(mut providers) = installation.providers.lock() else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let (status, result) = providers.call(request);
    (status, Json(result)).into_response()
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args().skip(1).collect();
    let [path, id, generation, broker_uid] = args.as_slice() else {
        return Err(io::Error::other(
            "Expected socket path, installation, generation and broker UID",
        )
        .into());
    };
    let installation = Arc::new(Installation {
        id: id.clone(),
        generation: generation.parse::<u64>()?.to_string(),
        broker_uid: broker_uid.parse()?,
        providers: Mutex::new(Providers::default()),
    });
    let socket = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o660))?;
    let router = Router::new()
        .route(
            "/v1/ready",
            get(|| async { Json(json!({ "ready": true })) }),
        )
        .route("/v1/probe", post(probe))
        .layer(DefaultBodyLimit::max(4096))
        .route_layer(middleware::from_fn_with_state(
            installation.clone(),
            authorize,
        ))
        .with_state(installation);
    axum::serve(
        socket,
        router.into_make_service_with_connect_info::<PeerUid>(),
    )
    .await?;
    Ok(())
}
