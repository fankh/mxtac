//! Packet capture module.
//!
//! Provides the `PacketCapture` trait and a libpcap-based implementation.

pub mod pcap_capture;

pub use pcap_capture::PcapCapture;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A raw captured packet with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawPacket {
    pub timestamp: DateTime<Utc>,
    pub data: Vec<u8>,
    pub length: usize,
    /// The capture length (may be less than `length` when snap-len is applied).
    pub caplen: usize,
}
