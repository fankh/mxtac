//! Health check HTTP endpoint for MxGuard.
//!
//! Exposes a lightweight HTTP server (via axum) on a configurable address
//! so orchestrators (systemd, Kubernetes, etc.) can probe liveness.
//!
//! ## Endpoints
//!
//! | Path       | Method | Description |
//! |-----------|--------|-------------|
//! | `/healthz` | GET    | Liveness probe — always returns `200 {"status":"ok",...}` |
//! | `/readyz`  | GET    | Readiness probe — `200 "ready"` when started, `503 "not ready"` otherwise |

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

/// Build the axum Router for the health API.
///
/// Exposed as `pub(crate)` so unit tests can construct the app without
/// binding a real TCP socket.
pub(crate) fn make_router(state: HealthState) -> Router {
    let shared = Arc::new(state);
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .with_state(shared)
}

/// Start the health HTTP server. Runs until `shutdown` fires.
pub async fn serve_health(
    config: &HealthConfig,
    state: HealthState,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let app = make_router(state);

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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::watch;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Bind on an OS-assigned port, spawn the axum server as a background
    /// task, and return (base_url, shutdown_sender).
    ///
    /// The `_shutdown` sender must be kept alive by the caller for the server
    /// to remain running; dropping it triggers graceful shutdown.
    async fn start_test_server(started: bool) -> (String, watch::Sender<bool>) {
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

        // Port 0 → OS picks an available ephemeral port.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let base = format!("http://{addr}");

        let state = HealthState {
            agent_name: "test-agent".into(),
            version: "1.0.0-test".into(),
            started,
        };

        tokio::spawn(async move {
            axum::serve(listener, make_router(state))
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.changed().await;
                })
                .await
                .expect("server error");
        });

        (base, shutdown_tx)
    }

    // -----------------------------------------------------------------------
    // /healthz — liveness probe
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn healthz_returns_200() {
        let (base, _shutdown) = start_test_server(true).await;
        let resp = reqwest::get(format!("{base}/healthz")).await.unwrap();
        assert_eq!(resp.status().as_u16(), 200);
    }

    #[tokio::test]
    async fn healthz_response_has_status_ok() {
        let (base, _shutdown) = start_test_server(true).await;
        let body: serde_json::Value = reqwest::get(format!("{base}/healthz"))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(body["status"], "ok");
    }

    #[tokio::test]
    async fn healthz_response_has_agent_name() {
        let (base, _shutdown) = start_test_server(true).await;
        let body: serde_json::Value = reqwest::get(format!("{base}/healthz"))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(body["agent"], "test-agent");
    }

    #[tokio::test]
    async fn healthz_response_has_version() {
        let (base, _shutdown) = start_test_server(true).await;
        let body: serde_json::Value = reqwest::get(format!("{base}/healthz"))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(body["version"], "1.0.0-test");
    }

    #[tokio::test]
    async fn healthz_returns_json_object() {
        let (base, _shutdown) = start_test_server(true).await;
        let body: serde_json::Value = reqwest::get(format!("{base}/healthz"))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(body.is_object(), "expected JSON object, got: {body}");
    }

    // /healthz should return 200 regardless of started state (liveness ≠ readiness).
    #[tokio::test]
    async fn healthz_returns_200_even_when_not_started() {
        let (base, _shutdown) = start_test_server(false).await;
        let resp = reqwest::get(format!("{base}/healthz")).await.unwrap();
        assert_eq!(resp.status().as_u16(), 200);
    }

    // -----------------------------------------------------------------------
    // /readyz — readiness probe
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn readyz_returns_200_with_body_ready_when_started() {
        let (base, _shutdown) = start_test_server(true).await;
        let resp = reqwest::get(format!("{base}/readyz")).await.unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        assert_eq!(resp.text().await.unwrap(), "ready");
    }

    #[tokio::test]
    async fn readyz_returns_503_with_body_not_ready_when_not_started() {
        let (base, _shutdown) = start_test_server(false).await;
        let resp = reqwest::get(format!("{base}/readyz")).await.unwrap();
        assert_eq!(resp.status().as_u16(), 503);
        assert_eq!(resp.text().await.unwrap(), "not ready");
    }

    // -----------------------------------------------------------------------
    // Unknown routes
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn unknown_route_returns_404() {
        let (base, _shutdown) = start_test_server(true).await;
        let resp = reqwest::get(format!("{base}/metrics")).await.unwrap();
        assert_eq!(resp.status().as_u16(), 404);
    }

    // -----------------------------------------------------------------------
    // Default configuration
    // -----------------------------------------------------------------------

    #[test]
    fn default_health_listen_addr_uses_port_9001() {
        let config = HealthConfig::default();
        assert!(
            config.listen_addr.ends_with(":9001"),
            "default listen_addr should end with :9001, got: {}",
            config.listen_addr
        );
    }

    #[test]
    fn default_health_listen_addr_binds_all_interfaces() {
        let config = HealthConfig::default();
        assert!(
            config.listen_addr.starts_with("0.0.0.0:"),
            "default listen_addr should bind all interfaces (0.0.0.0), got: {}",
            config.listen_addr
        );
    }
}
