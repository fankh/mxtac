//! HTTP transport: batches OCSF network events and POSTs them to MxTac.

use std::time::Duration;

use reqwest::{header, Client};
use tracing::{debug, error, info, warn};

use crate::config::TransportConfig;
use crate::events::OcsfNetworkEvent;

/// Sends batches of OCSF network events over HTTP(S).
pub struct HttpTransport {
    client: Client,
    config: TransportConfig,
}

impl HttpTransport {
    pub fn new(config: &TransportConfig) -> anyhow::Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self {
            client,
            config: config.clone(),
        })
    }

    /// Send a batch of events with exponential back-off retry.
    pub async fn send_batch(&self, events: &[OcsfNetworkEvent]) -> anyhow::Result<()> {
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

    async fn try_send(&self, payload: &[u8]) -> anyhow::Result<()> {
        let mut req = self
            .client
            .post(&self.config.endpoint)
            .header(header::CONTENT_TYPE, "application/json")
            .body(payload.to_vec());

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
