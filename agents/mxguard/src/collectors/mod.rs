//! Collector modules for MxGuard EDR telemetry.
//!
//! Each collector is responsible for gathering one category of host events
//! (processes, file changes, network connections) and sending them through
//! a shared channel to the agent orchestrator.

pub mod process;
pub mod file;
pub mod network;
pub mod auth;

use crate::events::OcsfEvent;
use async_trait::async_trait;
use tokio::sync::mpsc;

/// Trait that all collectors implement.
#[async_trait]
pub trait Collector: Send + Sync {
    /// Human-readable name of this collector.
    fn name(&self) -> &'static str;

    /// Start the collection loop, emitting events on `tx`.
    /// The method should run until the provided `shutdown` signal fires.
    async fn run(
        &self,
        tx: mpsc::Sender<OcsfEvent>,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> anyhow::Result<()>;
}
