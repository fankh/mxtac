//! HTTP transport: batches OCSF events and POSTs them to the MxTac API.

use std::time::Duration;

use reqwest::{header, Client};
use tracing::{debug, error, info, warn};

use crate::config::TransportConfig;
use crate::events::OcsfEvent;

/// Sends batches of OCSF events over HTTP(S).
pub struct HttpTransport {
    client: Client,
    config: TransportConfig,
}

impl HttpTransport {
    /// Build a new transport from the given config.
    pub fn new(config: &TransportConfig) -> anyhow::Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;

        Ok(Self {
            client,
            config: config.clone(),
        })
    }

    /// Send a batch of events to the MxTac backend.
    ///
    /// Implements exponential back-off retry up to `retry_attempts`.
    pub async fn send_batch(&self, events: &[OcsfEvent]) -> anyhow::Result<()> {
        if events.is_empty() {
            return Ok(());
        }

        let payload = serde_json::to_vec(events)?;
        let total = events.len();

        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            match self.try_send(&payload).await {
                Ok(()) => {
                    info!("Sent batch of {total} events (attempt {attempt})");
                    return Ok(());
                }
                Err(e) if attempt >= self.config.retry_attempts => {
                    error!("Failed to send batch after {attempt} attempts: {e}");
                    return Err(e);
                }
                Err(e) => {
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
    async fn try_send(&self, payload: &[u8]) -> anyhow::Result<()> {
        let mut req = self
            .client
            .post(&self.config.endpoint)
            .header(header::CONTENT_TYPE, "application/json")
            .body(payload.to_vec());

        // Attach bearer token if configured.
        if !self.config.api_key.is_empty() {
            req = req.header(
                header::AUTHORIZATION,
                format!("Bearer {}", self.config.api_key),
            );
        }

        let resp = req.send().await?;
        let status = resp.status();

        if status.is_success() {
            debug!("Backend responded {status}");
            Ok(())
        } else {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Backend returned {status}: {body}");
        }
    }
}
