//! libpcap-based packet capture.
//!
//! Opens a network interface via `pcap`, applies a BPF filter, and streams
//! raw packets through a tokio channel.

use chrono::Utc;
use pcap::{Capture, Device};
use tokio::sync::mpsc;
use tracing::{debug, error, info};

use crate::capture::RawPacket;
use crate::config::CaptureConfig;

/// Captures packets from a live network interface using libpcap.
pub struct PcapCapture {
    config: CaptureConfig,
}

impl PcapCapture {
    pub fn new(config: &CaptureConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }

    /// Start capturing packets.
    ///
    /// This method blocks on the pcap read loop, so it should be spawned in
    /// a `tokio::task::spawn_blocking` context. Captured packets are sent
    /// through `tx`.
    pub fn run_blocking(&self, tx: mpsc::Sender<RawPacket>) -> anyhow::Result<()> {
        info!(
            "Opening capture on interface={} snaplen={} promisc={}",
            self.config.interface, self.config.snaplen, self.config.promiscuous
        );

        // Find the device matching the configured interface name.
        let devices = Device::list()?;
        let device = devices
            .into_iter()
            .find(|d| d.name == self.config.interface)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Interface '{}' not found. Available interfaces: see `pcap::Device::list()`",
                    self.config.interface
                )
            })?;

        let mut cap = Capture::from_device(device)?
            .promisc(self.config.promiscuous)
            .snaplen(self.config.snaplen)
            .buffer_size(self.config.buffer_size)
            .open()?;

        // Apply BPF filter.
        if !self.config.bpf_filter.is_empty() {
            cap.filter(&self.config.bpf_filter, true)?;
            debug!("BPF filter applied: {}", self.config.bpf_filter);
        }

        info!("Packet capture started on {}", self.config.interface);

        loop {
            match cap.next_packet() {
                Ok(packet) => {
                    let raw = RawPacket {
                        timestamp: Utc::now(),
                        data: packet.data.to_vec(),
                        length: packet.header.len as usize,
                        caplen: packet.header.caplen as usize,
                    };
                    // If the receiver has been dropped, stop capturing.
                    if tx.blocking_send(raw).is_err() {
                        info!("Packet channel closed, stopping capture");
                        break;
                    }
                }
                Err(pcap::Error::TimeoutExpired) => {
                    // No packet available within the timeout; loop back.
                    continue;
                }
                Err(e) => {
                    error!("Capture error: {e}");
                    break;
                }
            }
        }

        Ok(())
    }
}
