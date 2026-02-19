//! Agent orchestrator for MxGuard.
//!
//! Coordinates collectors, event batching, transport, and graceful shutdown.

use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tracing::{error, info};

use crate::collectors::process::ProcessCollector;
use crate::collectors::file::FileCollector;
use crate::collectors::network::NetworkCollector;
use crate::collectors::Collector;
use crate::config::Config;
use crate::events::ocsf::OcsfDevice;
use crate::events::OcsfEvent;
use crate::health::{self, HealthState};
use crate::transport::HttpTransport;

/// Top-level agent that owns the runtime lifecycle.
pub struct Agent {
    config: Config,
    device: OcsfDevice,
}

impl Agent {
    pub fn new(config: Config) -> Self {
        let device = OcsfDevice::from_current_host();
        Self { config, device }
    }

    /// Run the agent until a SIGINT / SIGTERM signal is received.
    pub async fn run(&self) -> anyhow::Result<()> {
        info!("MxGuard agent starting (name={})", self.config.agent.name);

        // Shutdown broadcast channel.
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        // Event channel shared by all collectors.
        let (event_tx, mut event_rx) = mpsc::channel::<OcsfEvent>(10_000);

        // --- Spawn collectors ---------------------------------------------------
        let mut collector_handles = Vec::new();

        if self.config.collectors.process.enabled {
            let collector = ProcessCollector::new(
                &self.config.collectors.process,
                self.device.clone(),
            );
            let tx = event_tx.clone();
            let rx = shutdown_rx.clone();
            collector_handles.push(tokio::spawn(async move {
                if let Err(e) = collector.run(tx, rx).await {
                    error!("Process collector error: {e}");
                }
            }));
        }

        if self.config.collectors.file.enabled {
            let collector = FileCollector::new(
                &self.config.collectors.file,
                self.device.clone(),
            );
            let tx = event_tx.clone();
            let rx = shutdown_rx.clone();
            collector_handles.push(tokio::spawn(async move {
                if let Err(e) = collector.run(tx, rx).await {
                    error!("File collector error: {e}");
                }
            }));
        }

        if self.config.collectors.network.enabled {
            let collector = NetworkCollector::new(
                &self.config.collectors.network,
                self.device.clone(),
            );
            let tx = event_tx.clone();
            let rx = shutdown_rx.clone();
            collector_handles.push(tokio::spawn(async move {
                if let Err(e) = collector.run(tx, rx).await {
                    error!("Network collector error: {e}");
                }
            }));
        }

        // Drop the original sender so the channel closes when all collectors stop.
        drop(event_tx);

        // --- Spawn health endpoint -----------------------------------------------
        let health_state = HealthState {
            agent_name: self.config.agent.name.clone(),
            version: env!("CARGO_PKG_VERSION").into(),
            started: true,
        };
        let health_config = self.config.health.clone();
        let health_shutdown = shutdown_rx.clone();
        let health_handle = tokio::spawn(async move {
            if let Err(e) = health::serve_health(&health_config, health_state, health_shutdown).await {
                error!("Health endpoint error: {e}");
            }
        });

        // --- Spawn transport (batched sender) ------------------------------------
        let transport = HttpTransport::new(&self.config.transport)?;
        let batch_size = self.config.transport.batch_size;
        let flush_interval = Duration::from_millis(self.config.transport.flush_interval_ms);

        let transport_handle = tokio::spawn(async move {
            let mut batch: Vec<OcsfEvent> = Vec::with_capacity(batch_size);
            let mut flush_timer = tokio::time::interval(flush_interval);

            loop {
                tokio::select! {
                    maybe_event = event_rx.recv() => {
                        match maybe_event {
                            Some(event) => {
                                batch.push(event);
                                if batch.len() >= batch_size {
                                    if let Err(e) = transport.send_batch(&batch).await {
                                        error!("Transport error: {e}");
                                    }
                                    batch.clear();
                                }
                            }
                            None => {
                                // All senders dropped — flush remaining and exit.
                                if !batch.is_empty() {
                                    let _ = transport.send_batch(&batch).await;
                                }
                                break;
                            }
                        }
                    }
                    _ = flush_timer.tick() => {
                        if !batch.is_empty() {
                            if let Err(e) = transport.send_batch(&batch).await {
                                error!("Transport flush error: {e}");
                            }
                            batch.clear();
                        }
                    }
                }
            }
        });

        // --- Wait for shutdown signal --------------------------------------------
        tokio::signal::ctrl_c().await?;
        info!("Received shutdown signal, stopping collectors...");

        // Notify all tasks.
        let _ = shutdown_tx.send(true);

        // Give collectors a moment to stop, then abort.
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            for h in collector_handles {
                let _ = h.await;
            }
        })
        .await;

        let _ = tokio::time::timeout(Duration::from_secs(2), transport_handle).await;
        health_handle.abort();

        info!("MxGuard agent stopped");
        Ok(())
    }
}
