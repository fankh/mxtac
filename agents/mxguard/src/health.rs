//! Health check HTTP endpoint for MxGuard.
//!
//! Exposes a lightweight HTTP server (via axum) on a configurable address
//! so orchestrators (systemd, Kubernetes, etc.) can probe liveness.

use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::get, Json, Router};
use serde::Serialize;
use tokio::sync::watch;
use tracing::info;

use crate::config::HealthConfig;

/// Shared state visible to the health endpoint.
#[derive(Debug, Clone)]
pub struct HealthState {
    pub agent_name: String,
    pub version: String,
    pub started: bool,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    agent: String,
    version: String,
}

/// Start the health HTTP server. Runs until `shutdown` fires.
pub async fn serve_health(
    config: &HealthConfig,
    state: HealthState,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let shared = Arc::new(state);

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .with_state(shared);

    let listener = tokio::net::TcpListener::bind(&config.listen_addr).await?;
    info!("Health endpoint listening on {}", config.listen_addr);

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown.changed().await;
        })
        .await?;

    Ok(())
}

async fn healthz(State(state): State<Arc<HealthState>>) -> impl IntoResponse {
    let body = HealthResponse {
        status: "ok",
        agent: state.agent_name.clone(),
        version: state.version.clone(),
    };
    (StatusCode::OK, Json(body))
}

async fn readyz(State(state): State<Arc<HealthState>>) -> impl IntoResponse {
    if state.started {
        (StatusCode::OK, "ready")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not ready")
    }
}
