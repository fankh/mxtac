//! Health check HTTP endpoint for MxWatch.
//!
//! Exposes a lightweight HTTP server (via axum) on a configurable address
//! so orchestrators (systemd, Kubernetes, etc.) can probe liveness and
//! readiness.
//!
//! ## Endpoints
//!
//! | Path       | Method | Description |
//! |-----------|--------|-------------|
//! | `/healthz` | GET    | Liveness probe — always returns `200 {"status":"ok",...}` |
//! | `/readyz`  | GET    | Readiness probe — `200 "ready"` when all checks pass, `503 "not ready"` otherwise |
//!
//! ## Readiness checks
//!
//! All three conditions must hold for the agent to report ready:
//! 1. **Capture running** — the packet capture backend is active.
//! 2. **Recent events** — at least one event batch was sent within the last 5 minutes.
//! 3. **Transport connected** — the last event batch was delivered successfully.

use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::get, Json, Router};
use serde::Serialize;
use tokio::sync::watch;
use tracing::info;

use crate::config::HealthConfig;

/// Maximum seconds since the last successful event-batch send for the agent
/// to be considered ready.  Events older than this window indicate a stalled
/// pipeline.
const RECENT_EVENT_WINDOW_SECS: u64 = 5 * 60; // 5 minutes

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

/// Shared health state updated by the capture and transport tasks at runtime.
///
/// All fields use lock-free atomics so that the health endpoint never blocks
/// the packet-processing hot path.  Clone the individual `Arc` handles and
/// pass them to the relevant tasks before constructing the health server.
#[derive(Debug, Clone)]
pub struct HealthState {
    pub agent_name: String,
    pub version: String,
    /// Set to `true` when the packet capture backend is actively running.
    pub capture_running: Arc<AtomicBool>,
    /// Unix timestamp (seconds) of the last successful event-batch delivery.
    /// `0` means no batch has ever been delivered.
    pub last_event_sent_secs: Arc<AtomicU64>,
    /// Set to `true` after the transport has successfully delivered a batch;
    /// cleared to `false` on delivery failure.
    pub transport_connected: Arc<AtomicBool>,
}

impl HealthState {
    pub fn new(agent_name: String, version: String) -> Self {
        Self {
            agent_name,
            version,
            capture_running: Arc::new(AtomicBool::new(false)),
            last_event_sent_secs: Arc::new(AtomicU64::new(0)),
            transport_connected: Arc::new(AtomicBool::new(false)),
        }
    }
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    agent: String,
    version: String,
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// Start the health HTTP server.  Runs until `shutdown` fires.
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

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Liveness probe — always `200 OK` as long as the process is up.
async fn healthz(State(state): State<Arc<HealthState>>) -> impl IntoResponse {
    let body = HealthResponse {
        status: "ok",
        agent: state.agent_name.clone(),
        version: state.version.clone(),
    };
    (StatusCode::OK, Json(body))
}

/// Readiness probe — `200` when all three conditions hold, `503` otherwise.
async fn readyz(State(state): State<Arc<HealthState>>) -> impl IntoResponse {
    let capture_ok = state.capture_running.load(Ordering::Relaxed);
    let transport_ok = state.transport_connected.load(Ordering::Relaxed);
    let events_ok = {
        let last_sent = state.last_event_sent_secs.load(Ordering::Relaxed);
        if last_sent == 0 {
            false
        } else {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            now.saturating_sub(last_sent) < RECENT_EVENT_WINDOW_SECS
        }
    };

    if capture_ok && transport_ok && events_ok {
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
    use std::sync::atomic::Ordering;
    use tokio::sync::watch;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Bind on an OS-assigned port, spawn the axum server as a background
    /// task, and return `(base_url, shutdown_sender)`.
    ///
    /// The `_shutdown` sender must be kept alive by the caller; dropping it
    /// triggers graceful shutdown.
    async fn start_test_server(
        capture_running: bool,
        events_recent: bool,
        transport_connected: bool,
    ) -> (String, watch::Sender<bool>) {
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let base = format!("http://{addr}");

        let state = HealthState::new("test-agent".into(), "1.0.0-test".into());
        state
            .capture_running
            .store(capture_running, Ordering::Relaxed);
        state
            .transport_connected
            .store(transport_connected, Ordering::Relaxed);
        if events_recent {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            state.last_event_sent_secs.store(now, Ordering::Relaxed);
        }
        // events_recent = false → last_event_sent_secs stays at 0 (never sent)

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

    /// Convenience: server where all readiness conditions are met.
    async fn start_ready_server() -> (String, watch::Sender<bool>) {
        start_test_server(true, true, true).await
    }

    /// Convenience: server where no readiness conditions are met.
    async fn start_not_ready_server() -> (String, watch::Sender<bool>) {
        start_test_server(false, false, false).await
    }

    // -----------------------------------------------------------------------
    // /healthz — liveness probe
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn healthz_returns_200() {
        let (base, _shutdown) = start_ready_server().await;
        let resp = reqwest::get(format!("{base}/healthz")).await.unwrap();
        assert_eq!(resp.status().as_u16(), 200);
    }

    #[tokio::test]
    async fn healthz_response_has_status_ok() {
        let (base, _shutdown) = start_ready_server().await;
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
        let (base, _shutdown) = start_ready_server().await;
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
        let (base, _shutdown) = start_ready_server().await;
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
        let (base, _shutdown) = start_ready_server().await;
        let body: serde_json::Value = reqwest::get(format!("{base}/healthz"))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(body.is_object(), "expected JSON object, got: {body}");
    }

    // /healthz must return 200 regardless of readiness state (liveness ≠ readiness).
    #[tokio::test]
    async fn healthz_returns_200_even_when_not_ready() {
        let (base, _shutdown) = start_not_ready_server().await;
        let resp = reqwest::get(format!("{base}/healthz")).await.unwrap();
        assert_eq!(resp.status().as_u16(), 200);
    }

    // -----------------------------------------------------------------------
    // /readyz — readiness probe
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn readyz_returns_200_when_all_conditions_met() {
        let (base, _shutdown) = start_ready_server().await;
        let resp = reqwest::get(format!("{base}/readyz")).await.unwrap();
        assert_eq!(resp.status().as_u16(), 200);
    }

    #[tokio::test]
    async fn readyz_body_is_ready_when_all_conditions_met() {
        let (base, _shutdown) = start_ready_server().await;
        let text = reqwest::get(format!("{base}/readyz"))
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert_eq!(text, "ready");
    }

    #[tokio::test]
    async fn readyz_returns_503_when_capture_not_running() {
        // transport connected + events recent, but capture is down
        let (base, _shutdown) = start_test_server(false, true, true).await;
        let resp = reqwest::get(format!("{base}/readyz")).await.unwrap();
        assert_eq!(resp.status().as_u16(), 503);
    }

    #[tokio::test]
    async fn readyz_returns_503_when_no_recent_events() {
        // capture running + transport connected, but no events ever sent
        let (base, _shutdown) = start_test_server(true, false, true).await;
        let resp = reqwest::get(format!("{base}/readyz")).await.unwrap();
        assert_eq!(resp.status().as_u16(), 503);
    }

    #[tokio::test]
    async fn readyz_returns_503_when_transport_not_connected() {
        // capture running + recent events, but transport failed
        let (base, _shutdown) = start_test_server(true, true, false).await;
        let resp = reqwest::get(format!("{base}/readyz")).await.unwrap();
        assert_eq!(resp.status().as_u16(), 503);
    }

    #[tokio::test]
    async fn readyz_returns_503_when_no_conditions_met() {
        let (base, _shutdown) = start_not_ready_server().await;
        let resp = reqwest::get(format!("{base}/readyz")).await.unwrap();
        assert_eq!(resp.status().as_u16(), 503);
    }

    #[tokio::test]
    async fn readyz_body_is_not_ready_when_not_ready() {
        let (base, _shutdown) = start_not_ready_server().await;
        let text = reqwest::get(format!("{base}/readyz"))
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert_eq!(text, "not ready");
    }

    // -----------------------------------------------------------------------
    // Unknown routes
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn unknown_route_returns_404() {
        let (base, _shutdown) = start_ready_server().await;
        let resp = reqwest::get(format!("{base}/metrics")).await.unwrap();
        assert_eq!(resp.status().as_u16(), 404);
    }

    // -----------------------------------------------------------------------
    // Default configuration
    // -----------------------------------------------------------------------

    #[test]
    fn default_health_listen_addr_uses_port_9002() {
        let config = HealthConfig::default();
        assert!(
            config.listen_addr.ends_with(":9002"),
            "default listen_addr should end with :9002, got: {}",
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

    // -----------------------------------------------------------------------
    // HealthState construction
    // -----------------------------------------------------------------------

    #[test]
    fn health_state_new_starts_with_capture_not_running() {
        let state = HealthState::new("mxwatch".into(), "1.0.0".into());
        assert!(!state.capture_running.load(Ordering::Relaxed));
    }

    #[test]
    fn health_state_new_starts_with_no_events_sent() {
        let state = HealthState::new("mxwatch".into(), "1.0.0".into());
        assert_eq!(state.last_event_sent_secs.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn health_state_new_starts_with_transport_not_connected() {
        let state = HealthState::new("mxwatch".into(), "1.0.0".into());
        assert!(!state.transport_connected.load(Ordering::Relaxed));
    }

    #[test]
    fn health_state_clone_shares_atomics() {
        let state = HealthState::new("mxwatch".into(), "1.0.0".into());
        let cloned = state.clone();
        // Mutating via clone should be visible in the original.
        cloned.capture_running.store(true, Ordering::Relaxed);
        assert!(state.capture_running.load(Ordering::Relaxed));
    }
}
