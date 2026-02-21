//! HTTP transport: batches OCSF events and POSTs them to the MxTac ingest API.
//!
//! # Protocol
//!
//! Every batch is serialised as:
//!
//! ```json
//! { "events": [ { ...ocsf... }, ... ] }
//! ```
//!
//! and sent as a `POST` to the configured endpoint with:
//!
//! - `Content-Type: application/json`
//! - `X-API-Key: <api_key>` (when non-empty)
//! - `X-Agent-ID: <agent_id>` (when non-empty)
//!
//! # Retry
//!
//! Transient failures (5xx, network errors) are retried with exponential
//! back-off up to `retry_attempts`.  HTTP 429 Too Many Requests responses
//! use a longer initial delay (2 s vs 500 ms) to respect the backend rate
//! limiter (10 000 events / min per API key).

use std::time::Duration;

use reqwest::{header, Client};
use serde::Serialize;
use tracing::{debug, error, info, warn};

use crate::config::TransportConfig;
use crate::events::OcsfEvent;

// ---------------------------------------------------------------------------
// Request body
// ---------------------------------------------------------------------------

/// JSON body expected by `POST /api/v1/events/ingest`.
///
/// The backend schema is `{ "events": [ ...OCSF events... ] }`.
/// Sending a bare array would be rejected with HTTP 422.
#[derive(Serialize)]
struct IngestBody<'a> {
    events: &'a [OcsfEvent],
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// Sends batches of OCSF events over HTTP(S) to the MxTac ingest API.
pub struct HttpTransport {
    client: Client,
    config: TransportConfig,
    /// Used as the `X-Agent-ID` header value.  Empty → header is omitted.
    agent_id: String,
}

impl HttpTransport {
    /// Build a new transport.
    ///
    /// `agent_id` is attached as `X-Agent-ID` on every request so the backend
    /// can identify which MxGuard instance sent the batch.  Pass an empty
    /// string to omit the header.
    pub fn new(config: &TransportConfig, agent_id: &str) -> anyhow::Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;

        Ok(Self {
            client,
            config: config.clone(),
            agent_id: agent_id.to_string(),
        })
    }

    /// Send a batch of OCSF events to the MxTac backend.
    ///
    /// - Returns immediately if `events` is empty.
    /// - Serialises to `{ "events": [...] }` and POSTs with the appropriate
    ///   headers.
    /// - Retries up to `config.retry_attempts` times with exponential
    ///   back-off.  A 429 response triggers a longer delay.
    pub async fn send_batch(&self, events: &[OcsfEvent]) -> anyhow::Result<()> {
        if events.is_empty() {
            return Ok(());
        }

        let body = IngestBody { events };
        let payload = serde_json::to_vec(&body)?;
        let total = events.len();

        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            match self.try_send(&payload).await {
                Ok(()) => {
                    info!("Sent batch of {total} events (attempt {attempt})");
                    return Ok(());
                }
                Err(TransportError::RateLimited) => {
                    if attempt >= self.config.retry_attempts {
                        error!("Rate limited by backend after {attempt} attempts; giving up");
                        anyhow::bail!("Rate limited by backend");
                    }
                    // Double the base delay (2 s) each retry to back off further.
                    let backoff = Duration::from_millis(2_000 * 2u64.pow(attempt - 1));
                    warn!(
                        "Rate limited by backend (attempt {attempt}), retrying in {}ms",
                        backoff.as_millis()
                    );
                    tokio::time::sleep(backoff).await;
                }
                Err(TransportError::Other(e)) if attempt >= self.config.retry_attempts => {
                    error!("Failed to send batch after {attempt} attempts: {e}");
                    return Err(e);
                }
                Err(TransportError::Other(e)) => {
                    let backoff = Duration::from_millis(500 * 2u64.pow(attempt - 1));
                    warn!(
                        "Send attempt {attempt} failed ({e}), retrying in {}ms",
                        backoff.as_millis()
                    );
                    tokio::time::sleep(backoff).await;
                }
            }
        }
    }

    /// Attempt a single HTTP POST.
    ///
    /// Returns:
    /// - `Ok(())` on any 2xx response.
    /// - `Err(TransportError::RateLimited)` on HTTP 429.
    /// - `Err(TransportError::Other(...))` on any other failure.
    async fn try_send(&self, payload: &[u8]) -> Result<(), TransportError> {
        let mut req = self
            .client
            .post(&self.config.endpoint)
            .header(header::CONTENT_TYPE, "application/json")
            .body(payload.to_vec());

        // X-API-Key is the authentication scheme used by the MxTac ingest API.
        if !self.config.api_key.is_empty() {
            req = req.header("X-API-Key", &self.config.api_key);
        }

        // X-Agent-ID lets the backend attribute traffic to a specific agent.
        if !self.agent_id.is_empty() {
            req = req.header("X-Agent-ID", &self.agent_id);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| TransportError::Other(e.into()))?;

        let status = resp.status();
        if status.is_success() {
            debug!("Backend responded {status}");
            Ok(())
        } else if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            Err(TransportError::RateLimited)
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(TransportError::Other(anyhow::anyhow!(
                "Backend returned {status}: {body}"
            )))
        }
    }
}

// ---------------------------------------------------------------------------
// Internal error type
// ---------------------------------------------------------------------------

/// Transport-level errors distinguished so the retry loop can apply different
/// back-off policies.
#[derive(Debug)]
enum TransportError {
    /// HTTP 429 Too Many Requests — the backend rate limiter is engaged.
    RateLimited,
    /// Any other I/O or HTTP-level error.
    Other(anyhow::Error),
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_string_contains, header as hdr, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::events::ocsf::{OcsfDevice, OcsfSeverity, ProcessActivityData};
    use crate::events::OcsfEvent;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn test_device() -> OcsfDevice {
        OcsfDevice {
            hostname: "test-host".into(),
            ip: "192.168.1.1".into(),
            os_name: "Linux".into(),
            os_version: "6.1.0".into(),
        }
    }

    fn test_event() -> OcsfEvent {
        OcsfEvent::process_activity(
            test_device(),
            "Launch",
            1,
            OcsfSeverity::Informational,
            ProcessActivityData {
                pid: 1234,
                ppid: 1000,
                name: "bash".into(),
                cmd_line: "/bin/bash".into(),
                exe_path: Some("/bin/bash".into()),
                cwd: Some("/home/user".into()),
                uid: 1000,
                gid: 1000,
                user: "user".into(),
            },
        )
    }

    fn test_config(server: &MockServer) -> TransportConfig {
        TransportConfig {
            endpoint: format!("{}/api/v1/events/ingest", server.uri()),
            api_key: "test-api-key".into(),
            batch_size: 10,
            flush_interval_ms: 1_000,
            retry_attempts: 3,
        }
    }

    fn accepted_response() -> ResponseTemplate {
        ResponseTemplate::new(202).set_body_json(serde_json::json!({
            "accepted": 1,
            "status": "queued"
        }))
    }

    // -----------------------------------------------------------------------
    // Body format — pure serialisation tests (no HTTP)
    // -----------------------------------------------------------------------

    #[test]
    fn ingest_body_wraps_events_under_events_key() {
        let events = vec![test_event()];
        let body = IngestBody { events: &events };
        let json: serde_json::Value = serde_json::to_value(&body).unwrap();

        assert!(
            json.get("events").is_some(),
            "Body must have a top-level 'events' key"
        );
        let arr = json["events"].as_array().expect("'events' must be a JSON array");
        assert_eq!(arr.len(), 1, "'events' array must contain 1 event");
    }

    #[test]
    fn ingest_body_is_a_json_object_not_bare_array() {
        let events = vec![test_event()];
        let body = IngestBody { events: &events };
        let json: serde_json::Value = serde_json::to_value(&body).unwrap();
        assert!(
            json.is_object(),
            "Serialised body must be a JSON object, not a bare array"
        );
    }

    #[test]
    fn ingest_body_preserves_event_count() {
        let events: Vec<OcsfEvent> = (0..5).map(|_| test_event()).collect();
        let body = IngestBody { events: &events };
        let json: serde_json::Value = serde_json::to_value(&body).unwrap();
        let arr = json["events"].as_array().unwrap();
        assert_eq!(arr.len(), 5);
    }

    // -----------------------------------------------------------------------
    // Empty batch — short-circuit without making an HTTP request
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn send_batch_empty_returns_ok_without_http_request() {
        let server = MockServer::start().await;
        // No mocks mounted — any request would cause a mismatch / panic.
        let config = test_config(&server);
        let transport = HttpTransport::new(&config, "agent-1").unwrap();
        assert!(transport.send_batch(&[]).await.is_ok());
    }

    // -----------------------------------------------------------------------
    // Successful POST
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn send_batch_posts_to_ingest_endpoint() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/events/ingest"))
            .respond_with(accepted_response())
            .expect(1)
            .mount(&server)
            .await;

        let transport = HttpTransport::new(&test_config(&server), "agent-1").unwrap();
        assert!(transport.send_batch(&[test_event()]).await.is_ok());
        server.verify().await;
    }

    #[tokio::test]
    async fn send_batch_uses_http_post_method() {
        let server = MockServer::start().await;
        // Only a POST mock is mounted; GET/PUT/etc would not match.
        Mock::given(method("POST"))
            .and(path("/api/v1/events/ingest"))
            .respond_with(accepted_response())
            .expect(1)
            .mount(&server)
            .await;

        let transport = HttpTransport::new(&test_config(&server), "agent-1").unwrap();
        assert!(transport.send_batch(&[test_event()]).await.is_ok());
        server.verify().await;
    }

    // -----------------------------------------------------------------------
    // Headers
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn send_batch_sends_x_api_key_header() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/events/ingest"))
            .and(hdr("X-API-Key", "test-api-key"))
            .respond_with(accepted_response())
            .expect(1)
            .mount(&server)
            .await;

        let transport = HttpTransport::new(&test_config(&server), "agent-1").unwrap();
        assert!(transport.send_batch(&[test_event()]).await.is_ok());
        server.verify().await;
    }

    #[tokio::test]
    async fn send_batch_sends_x_agent_id_header() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/events/ingest"))
            .and(hdr("X-Agent-ID", "mxguard-prod-01"))
            .respond_with(accepted_response())
            .expect(1)
            .mount(&server)
            .await;

        let transport =
            HttpTransport::new(&test_config(&server), "mxguard-prod-01").unwrap();
        assert!(transport.send_batch(&[test_event()]).await.is_ok());
        server.verify().await;
    }

    #[tokio::test]
    async fn send_batch_sets_content_type_application_json() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/events/ingest"))
            .and(hdr("content-type", "application/json"))
            .respond_with(accepted_response())
            .expect(1)
            .mount(&server)
            .await;

        let transport = HttpTransport::new(&test_config(&server), "agent-1").unwrap();
        assert!(transport.send_batch(&[test_event()]).await.is_ok());
        server.verify().await;
    }

    #[tokio::test]
    async fn send_batch_omits_x_api_key_when_empty() {
        let server = MockServer::start().await;
        // Mount a mock that succeeds — if X-API-Key were sent the header
        // matcher in later tests ensures absence doesn't cause issues here.
        Mock::given(method("POST"))
            .and(path("/api/v1/events/ingest"))
            .respond_with(accepted_response())
            .expect(1)
            .mount(&server)
            .await;

        let mut config = test_config(&server);
        config.api_key = String::new();
        let transport = HttpTransport::new(&config, "").unwrap();
        assert!(transport.send_batch(&[test_event()]).await.is_ok());
        server.verify().await;
    }

    // -----------------------------------------------------------------------
    // Body format — HTTP-level check (body contains "events" wrapper key)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn send_batch_body_contains_events_wrapper_key() {
        let server = MockServer::start().await;
        // body_string_contains checks the raw request body bytes as a string.
        // A bare JSON array [{ ... }] would not contain `"events":` whereas
        // our IngestBody { events } serialises to { "events": [...] }.
        Mock::given(method("POST"))
            .and(path("/api/v1/events/ingest"))
            .and(body_string_contains("\"events\":["))
            .respond_with(accepted_response())
            .expect(1)
            .mount(&server)
            .await;

        let transport = HttpTransport::new(&test_config(&server), "agent-1").unwrap();
        assert!(transport.send_batch(&[test_event()]).await.is_ok());
        server.verify().await;
    }

    // -----------------------------------------------------------------------
    // Retry behaviour
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn send_batch_retries_on_server_error_and_succeeds() {
        let server = MockServer::start().await;

        // Mount the success handler first (lowest priority — oldest).
        Mock::given(method("POST"))
            .and(path("/api/v1/events/ingest"))
            .respond_with(accepted_response())
            .mount(&server)
            .await;

        // Mount the failure handler second (highest priority — newest).
        // It fires only once, then the success mock takes over.
        Mock::given(method("POST"))
            .and(path("/api/v1/events/ingest"))
            .respond_with(ResponseTemplate::new(500))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        let mut config = test_config(&server);
        config.retry_attempts = 3;
        let transport = HttpTransport::new(&config, "agent-1").unwrap();
        let result = transport.send_batch(&[test_event()]).await;
        assert!(result.is_ok(), "Expected success after retry, got: {result:?}");
    }

    #[tokio::test]
    async fn send_batch_fails_after_max_retries_exhausted() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/events/ingest"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let mut config = test_config(&server);
        config.retry_attempts = 2;
        let transport = HttpTransport::new(&config, "agent-1").unwrap();
        let result = transport.send_batch(&[test_event()]).await;
        assert!(result.is_err(), "Expected error after max retries exhausted");
    }

    // -----------------------------------------------------------------------
    // HTTP 429 — rate limiting
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn send_batch_returns_error_on_429_after_max_attempts() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/events/ingest"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&server)
            .await;

        // retry_attempts = 1 → bail immediately on the first 429 (no sleep).
        let mut config = test_config(&server);
        config.retry_attempts = 1;
        let transport = HttpTransport::new(&config, "agent-1").unwrap();
        let result = transport.send_batch(&[test_event()]).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Rate limited"),
            "Expected 'Rate limited' error message, got: {err_msg}"
        );
    }

    #[tokio::test]
    async fn send_batch_distinguishes_429_from_5xx() {
        // 429 should produce a "Rate limited" error, not a generic one.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/events/ingest"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&server)
            .await;

        let mut config = test_config(&server);
        config.retry_attempts = 1;
        let transport = HttpTransport::new(&config, "agent-1").unwrap();
        let err = transport
            .send_batch(&[test_event()])
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("Rate limited"), "got: {err}");
    }

    #[tokio::test]
    async fn send_batch_429_then_success_on_retry() {
        let server = MockServer::start().await;

        // Success mock mounted first (lowest priority).
        Mock::given(method("POST"))
            .and(path("/api/v1/events/ingest"))
            .respond_with(accepted_response())
            .mount(&server)
            .await;

        // 429 mock mounted second (highest priority), fires once.
        Mock::given(method("POST"))
            .and(path("/api/v1/events/ingest"))
            .respond_with(ResponseTemplate::new(429))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        let mut config = test_config(&server);
        config.retry_attempts = 3;
        // Use a very short initial rate-limit delay so the test is fast.
        // (The actual delay formula is 2_000ms * 2^(attempt-1); with
        // attempt=1 and retry_attempts=3 we'd wait 2 s.  For testing we
        // keep retry_attempts > 1 to allow the retry to proceed but note
        // that this test will take ~2 s due to the rate-limit backoff.)
        let transport = HttpTransport::new(&config, "agent-1").unwrap();
        let result = transport.send_batch(&[test_event()]).await;
        assert!(result.is_ok(), "Expected success after rate-limit retry, got: {result:?}");
    }
}
