//! Detection engines for MxWatch.
//!
//! Detectors analyze parsed flow data and raise alerts when suspicious
//! patterns are identified.

pub mod c2_beacon;
pub mod data_exfil;
pub mod dga;
pub mod dns_tunnel;
pub mod port_scan;
pub mod proto_anomaly;

use serde::{Deserialize, Serialize};

/// An alert raised by a detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub detector: String,
    pub severity: AlertSeverity,
    pub description: String,
    pub evidence: serde_json::Value,
}

/// Severity levels for detector alerts.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl AlertSeverity {
    pub fn ocsf_id(&self) -> u8 {
        match self {
            Self::Low => 2,
            Self::Medium => 3,
            Self::High => 4,
            Self::Critical => 5,
        }
    }
}
