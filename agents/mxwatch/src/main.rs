//! MxWatch -- Network Detection & Response agent for the MxTac platform.
//!
//! Captures network traffic (libpcap or AF_PACKET + MMAP on Linux), parses
//! protocols (TCP, UDP, DNS, HTTP, TLS), runs detection engines (DNS
//! tunneling, port scanning), and ships OCSF events to the MxTac ingest API.

mod capture;
mod config;
mod detectors;
mod events;
mod parsers;
mod transport;

use std::net::IpAddr;
use std::time::Duration;

use clap::Parser;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use tokio::sync::mpsc;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use crate::capture::PcapCapture;
#[cfg(target_os = "linux")]
use crate::capture::AfPacketCapture;
use crate::detectors::dns_tunnel::DnsTunnelDetector;
use crate::detectors::port_scan::PortScanDetector;
use crate::events::ocsf::{OcsfDevice, OcsfNetworkEvent};
use crate::parsers::dns;
use crate::parsers::http as http_parser;
use crate::parsers::tcp;
use crate::parsers::tls;
use crate::parsers::udp;
use crate::transport::HttpTransport;

/// MxWatch NDR agent.
#[derive(Parser, Debug)]
#[command(name = "mxwatch", version, about = "MxWatch NDR Agent for MxTac")]
struct Cli {
    /// Path to TOML configuration file.
    #[arg(short, long, default_value = "/etc/mxwatch/mxwatch.toml")]
    config: String,

    /// Override log level.
    #[arg(short, long)]
    log_level: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let cfg = if std::path::Path::new(&cli.config).exists() {
        config::Config::from_file(&cli.config)?
    } else {
        tracing::warn!(
            "Config file not found at {}, using defaults",
            cli.config
        );
        config::Config::default_config()
    };

    let log_level = cli.log_level.as_deref().unwrap_or(&cfg.agent.log_level);
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(log_level)),
        )
        .with_target(true)
        .with_thread_ids(true)
        .init();

    info!("MxWatch v{} starting", env!("CARGO_PKG_VERSION"));

    let device = OcsfDevice::from_current_host();

    // --- Packet capture channel ------------------------------------------------
    let (pkt_tx, mut pkt_rx) = mpsc::channel::<capture::RawPacket>(10_000);

    // Start capture in a blocking thread.
    // On Linux, prefer AF_PACKET + MMAP when `use_afpacket = true`.
    #[cfg(target_os = "linux")]
    let capture_handle = if cfg.capture.use_afpacket {
        info!("Using AF_PACKET MMAP zero-copy capture backend");
        let cap = AfPacketCapture::new(&cfg.capture);
        tokio::task::spawn_blocking(move || {
            if let Err(e) = cap.run_blocking(pkt_tx) {
                error!("AF_PACKET capture error: {e}");
            }
        })
    } else {
        let pcap = PcapCapture::new(&cfg.capture);
        tokio::task::spawn_blocking(move || {
            if let Err(e) = pcap.run_blocking(pkt_tx) {
                error!("Packet capture error: {e}");
            }
        })
    };

    #[cfg(not(target_os = "linux"))]
    let capture_handle = {
        let pcap = PcapCapture::new(&cfg.capture);
        tokio::task::spawn_blocking(move || {
            if let Err(e) = pcap.run_blocking(pkt_tx) {
                error!("Packet capture error: {e}");
            }
        })
    };

    // --- Event channel to transport --------------------------------------------
    let (evt_tx, mut evt_rx) = mpsc::channel::<OcsfNetworkEvent>(10_000);

    // --- Transport task --------------------------------------------------------
    let transport = HttpTransport::new(&cfg.transport)?;
    let batch_size = cfg.transport.batch_size;
    let flush_interval = Duration::from_millis(cfg.transport.flush_interval_ms);

    let transport_handle = tokio::spawn(async move {
        let mut batch: Vec<OcsfNetworkEvent> = Vec::with_capacity(batch_size);
        let mut flush_timer = tokio::time::interval(flush_interval);

        loop {
            tokio::select! {
                maybe_event = evt_rx.recv() => {
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

    // --- Detectors (stateful) --------------------------------------------------
    let mut dns_detector = DnsTunnelDetector::new(&cfg.detectors.dns_tunnel);
    let mut scan_detector = PortScanDetector::new(&cfg.detectors.port_scan);

    // --- Main packet processing loop -------------------------------------------
    info!("Entering packet processing loop");

    let evt_tx_clone = evt_tx.clone();
    let device_clone = device.clone();
    let http_patterns = cfg.parsers.http.suspicious_patterns.clone();

    let processing_handle = tokio::spawn(async move {
        while let Some(raw) = pkt_rx.recv().await {
            // Parse Ethernet frame.
            let eth = match EthernetPacket::new(&raw.data) {
                Some(e) => e,
                None => continue,
            };

            // Only handle IPv4 for now.
            if eth.get_ethertype() != EtherTypes::Ipv4 {
                continue;
            }

            let ipv4 = match Ipv4Packet::new(eth.payload()) {
                Some(ip) => ip,
                None => continue,
            };

            let src_ip = IpAddr::V4(ipv4.get_source());
            let dst_ip = IpAddr::V4(ipv4.get_destination());

            match ipv4.get_next_level_protocol() {
                IpNextHeaderProtocols::Tcp => {
                    let tcp_data = ipv4.payload();
                    let tcp_info = match tcp::parse_tcp(tcp_data) {
                        Some(t) => t,
                        None => continue,
                    };

                    // Port scan detection on SYN packets.
                    if tcp::is_syn_only(&tcp_info) {
                        if let Some(alert) = scan_detector.record(
                            &src_ip.to_string(),
                            tcp_info.dst_port,
                        ) {
                            let event = OcsfNetworkEvent::from_alert(
                                device_clone.clone(),
                                src_ip,
                                tcp_info.src_port,
                                dst_ip,
                                tcp_info.dst_port,
                                "TCP",
                                &alert,
                            );
                            let _ = evt_tx_clone.send(event).await;
                        }
                    }

                    // Try HTTP parsing on common ports.
                    if tcp_info.payload_len > 0 {
                        let payload_start = (tcp_data.len() - tcp_info.payload_len).min(tcp_data.len());
                        let payload = &tcp_data[payload_start..];

                        if let Some(http_info) = http_parser::parse_http_request(payload) {
                            if http_parser::is_suspicious_request(&http_info, &http_patterns) {
                                let event = OcsfNetworkEvent::traffic(
                                    device_clone.clone(),
                                    src_ip,
                                    tcp_info.src_port,
                                    dst_ip,
                                    tcp_info.dst_port,
                                    "HTTP",
                                    4, // High
                                );
                                let _ = evt_tx_clone.send(event).await;
                            }
                        }

                        // Try TLS ClientHello parsing.
                        if let Some(tls_info) = tls::parse_tls_client_hello(payload) {
                            if tls_info.sni.is_some() {
                                // Log TLS SNI at informational level.
                                let event = OcsfNetworkEvent::traffic(
                                    device_clone.clone(),
                                    src_ip,
                                    tcp_info.src_port,
                                    dst_ip,
                                    tcp_info.dst_port,
                                    "TLS",
                                    1, // Informational
                                );
                                let _ = evt_tx_clone.send(event).await;
                            }
                        }
                    }
                }

                IpNextHeaderProtocols::Udp => {
                    let udp_data = ipv4.payload();
                    let udp_info = match udp::parse_udp(udp_data) {
                        Some(u) => u,
                        None => continue,
                    };

                    // DNS parsing on port 53.
                    if udp_info.src_port == 53 || udp_info.dst_port == 53 {
                        let payload_start = 8.min(udp_data.len()); // UDP header = 8 bytes
                        let payload = &udp_data[payload_start..];

                        if let Some(dns_info) = dns::parse_dns(payload) {
                            if let Some(alert) = dns_detector.evaluate(&dns_info) {
                                let event = OcsfNetworkEvent::from_alert(
                                    device_clone.clone(),
                                    src_ip,
                                    udp_info.src_port,
                                    dst_ip,
                                    udp_info.dst_port,
                                    "DNS",
                                    &alert,
                                );
                                let _ = evt_tx_clone.send(event).await;
                            }
                        }
                    }
                }

                _ => {
                    // Ignore other protocols.
                }
            }
        }
    });

    // --- Wait for shutdown signal (Ctrl+C) -------------------------------------
    tokio::signal::ctrl_c().await?;
    info!("Shutdown signal received");

    // Drop the event sender to close the transport channel.
    drop(evt_tx);

    // Cancel capture.
    capture_handle.abort();

    // Wait for processing and transport to drain.
    let _ = tokio::time::timeout(Duration::from_secs(5), processing_handle).await;
    let _ = tokio::time::timeout(Duration::from_secs(3), transport_handle).await;

    info!("MxWatch agent stopped");
    Ok(())
}
