//! Packet capture module.
//!
//! Provides two capture backends:
//! * [`PcapCapture`] — libpcap (cross-platform, default)
//! * [`AfPacketCapture`] — AF_PACKET + MMAP zero-copy ring buffer (Linux only)

pub mod pcap_capture;

pub use pcap_capture::PcapCapture;

#[cfg(target_os = "linux")]
pub mod afpacket_capture;

#[cfg(target_os = "linux")]
pub use afpacket_capture::AfPacketCapture;

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
