//! MxWatch -- Network Detection & Response agent for the MxTac platform.
//!
//! Captures network traffic (libpcap or AF_PACKET + MMAP on Linux), parses
//! protocols (TCP, UDP, DNS, HTTP, TLS), runs detection engines (DNS
//! tunneling, port scanning), and ships OCSF events to the MxTac ingest API.

mod capture;
mod config;
mod detectors;
mod events;
mod health;
mod parsers;
mod resource;
mod transport;

use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::Parser;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::Packet;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use crate::capture::PcapCapture;
#[cfg(target_os = "linux")]
use crate::capture::AfPacketCapture;
use crate::detectors::c2_beacon::C2BeaconDetector;
use crate::detectors::dns_tunnel::DnsTunnelDetector;
use crate::detectors::port_scan::PortScanDetector;
use crate::detectors::proto_anomaly::ProtoAnomalyDetector;
use crate::events::ocsf::{OcsfDevice, OcsfNetworkEvent};
use crate::parsers::dns;
use crate::parsers::http as http_parser;
use crate::parsers::rdp as rdp_parser;
use crate::parsers::smb as smb_parser;
use crate::parsers::ssh as ssh_parser;
use crate::parsers::tcp;
use crate::parsers::tls;
use crate::parsers::udp;
use crate::resource::ResourceMonitor;
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

/// Return the current time as Unix seconds.
fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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

    // --- Health state ----------------------------------------------------------
    // Create shared atomic handles used by capture and transport tasks to
    // update the health readiness signals without blocking.
    let health_state = health::HealthState::new(
        cfg.agent.name.clone(),
        env!("CARGO_PKG_VERSION").to_string(),
    );
    let capture_running = health_state.capture_running.clone();
    let transport_connected = health_state.transport_connected.clone();
    let last_event_sent_secs = health_state.last_event_sent_secs.clone();

    // --- Health server ---------------------------------------------------------
    let (health_shutdown_tx, health_shutdown_rx) = tokio::sync::watch::channel(false);
    let health_cfg = cfg.health.clone();
    let health_handle = tokio::spawn(async move {
        if let Err(e) = health::serve_health(&health_cfg, health_state, health_shutdown_rx).await {
            error!("Health server error: {e}");
        }
    });

    // --- Resource monitor -------------------------------------------------------
    // Samples CPU% and RSS every `check_interval_ms`; shares metrics with the
    // packet-processing loop via a lock-free Arc<ResourceSnapshot>.
    let (resource_monitor, resource_snapshot) =
        ResourceMonitor::new(cfg.resources.clone());
    let resource_cfg = cfg.resources.clone();

    tokio::spawn(async move {
        resource_monitor.run().await;
    });

    // --- Packet capture channel ------------------------------------------------
    let (pkt_tx, mut pkt_rx) = mpsc::channel::<capture::RawPacket>(10_000);

    // Start capture in a blocking thread.
    // On Linux, prefer AF_PACKET + MMAP when `use_afpacket = true`.
    capture_running.store(true, Ordering::Relaxed);

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
                                match transport.send_batch(&batch).await {
                                    Ok(()) => {
                                        transport_connected.store(true, Ordering::Relaxed);
                                        last_event_sent_secs.store(now_unix_secs(), Ordering::Relaxed);
                                    }
                                    Err(e) => {
                                        error!("Transport error: {e}");
                                        transport_connected.store(false, Ordering::Relaxed);
                                    }
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
                        match transport.send_batch(&batch).await {
                            Ok(()) => {
                                transport_connected.store(true, Ordering::Relaxed);
                                last_event_sent_secs.store(now_unix_secs(), Ordering::Relaxed);
                            }
                            Err(e) => {
                                error!("Transport flush error: {e}");
                                transport_connected.store(false, Ordering::Relaxed);
                            }
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
    let proto_detector = ProtoAnomalyDetector::new(&cfg.detectors.proto_anomaly);
    let mut c2_detector = C2BeaconDetector::new(&cfg.detectors.c2_beacon);

    // --- Main packet processing loop -------------------------------------------
    info!("Entering packet processing loop");

    let evt_tx_clone = evt_tx.clone();
    let device_clone = device.clone();
    let http_patterns = cfg.parsers.http.suspicious_patterns.clone();
    let smb_enabled = cfg.parsers.smb.enabled;
    let ssh_enabled = cfg.parsers.ssh.enabled;
    let ssh_sw_blocklist = cfg.parsers.ssh.software_blocklist.clone();
    let rdp_enabled = cfg.parsers.rdp.enabled;

    let processing_handle = tokio::spawn(async move {
        let mut packet_count: u64 = 0;

        while let Some(raw) = pkt_rx.recv().await {
            packet_count += 1;

            // ── Resource limits check (every 100 packets) ──────────────────
            // Reads the latest snapshot published by the background monitor.
            // Applies a short adaptive sleep when CPU or RAM limits are
            // exceeded to reduce throughput and prevent runaway resource use.
            if resource_cfg.enabled && packet_count % 100 == 0 {
                let cpu_pct = resource_snapshot.cpu_pct();
                let rss_mb  = resource_snapshot.rss_mb();

                if rss_mb > resource_cfg.max_ram_mb {
                    // RAM over limit: pause for 50 ms to allow GC pressure to
                    // subside before processing the next batch.
                    warn!(
                        rss_mb,
                        limit_mb = resource_cfg.max_ram_mb,
                        "resource: RAM backpressure — pausing packet processing"
                    );
                    tokio::time::sleep(Duration::from_millis(50)).await;
                } else if cpu_pct > resource_cfg.max_cpu_pct {
                    // CPU over limit: sleep proportionally to the overage so
                    // that the effective processing rate decreases toward the
                    // target.  Sleep is clamped to [1, 100] ms.
                    let overage_ratio = cpu_pct / resource_cfg.max_cpu_pct - 1.0;
                    let sleep_ms = ((overage_ratio * 20.0) as u64).clamp(1, 100);
                    tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
                }
            }
            // ──────────────────────────────────────────────────────────────
            // Parse Ethernet frame.
            let eth = match EthernetPacket::new(&raw.data) {
                Some(e) => e,
                None => continue,
            };

            // Parse IP layer — support both IPv4 and IPv6.
            let (src_ip, dst_ip, next_proto, transport_data) = match eth.get_ethertype() {
                EtherTypes::Ipv4 => {
                    let ipv4 = match Ipv4Packet::new(eth.payload()) {
                        Some(p) => p,
                        None => continue,
                    };
                    (
                        IpAddr::V4(ipv4.get_source()),
                        IpAddr::V4(ipv4.get_destination()),
                        ipv4.get_next_level_protocol(),
                        ipv4.payload().to_vec(),
                    )
                }
                EtherTypes::Ipv6 => {
                    let ipv6 = match Ipv6Packet::new(eth.payload()) {
                        Some(p) => p,
                        None => continue,
                    };
                    (
                        IpAddr::V6(ipv6.get_source()),
                        IpAddr::V6(ipv6.get_destination()),
                        ipv6.get_next_header(),
                        ipv6.payload().to_vec(),
                    )
                }
                _ => continue,
            };

            match next_proto {
                IpNextHeaderProtocols::Tcp => {
                    let tcp_data = transport_data.as_slice();
                    let tcp_info = match tcp::parse_tcp(tcp_data) {
                        Some(t) => t,
                        None => continue,
                    };

                    // Port scan detection on SYN packets (SYN scan).
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

                    // Stealth scan detection: XMAS and NULL scan techniques.
                    if tcp::is_xmas_scan(&tcp_info) || tcp::is_null_scan(&tcp_info) {
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

                    // C2 beacon detection on all TCP flows.
                    if let Some(alert) = c2_detector.record_packet(
                        &src_ip.to_string(),
                        &dst_ip.to_string(),
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

                    // Try HTTP / TLS parsing on packets that carry payload data.
                    if tcp_info.payload_len > 0 {
                        let payload = tcp::parse_tcp_payload(tcp_data, &tcp_info);

                        if let Some(http_info) = http_parser::parse_http(payload) {
                            let suspicious = match http_info.direction {
                                http_parser::HttpDirection::Request => {
                                    http_parser::is_suspicious_request(&http_info, &http_patterns)
                                }
                                http_parser::HttpDirection::Response => {
                                    http_parser::is_suspicious_response(&http_info)
                                }
                            };
                            if suspicious {
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

                        // SMB2/CIFS parsing on port 445.
                        if smb_enabled && smb_parser::is_smb_port(tcp_info.dst_port) {
                            if let Some(smb_info) = smb_parser::parse_smb(payload) {
                                if smb_parser::is_suspicious_smb(&smb_info) {
                                    let event = OcsfNetworkEvent::traffic(
                                        device_clone.clone(),
                                        src_ip,
                                        tcp_info.src_port,
                                        dst_ip,
                                        tcp_info.dst_port,
                                        "SMB",
                                        3, // Medium severity
                                    );
                                    let _ = evt_tx_clone.send(event).await;
                                }
                            }
                        }

                        // SSH banner and binary-packet parsing on port 22.
                        if ssh_enabled && ssh_parser::is_ssh_port(tcp_info.dst_port) {
                            if let Some(ssh_info) = ssh_parser::parse_ssh(payload) {
                                if ssh_parser::is_suspicious_ssh(&ssh_info, &ssh_sw_blocklist) {
                                    let event = OcsfNetworkEvent::traffic(
                                        device_clone.clone(),
                                        src_ip,
                                        tcp_info.src_port,
                                        dst_ip,
                                        tcp_info.dst_port,
                                        "SSH",
                                        3, // Medium severity
                                    );
                                    let _ = evt_tx_clone.send(event).await;
                                }
                            }
                        }

                        // RDP connection-request parsing on port 3389.
                        if rdp_enabled && rdp_parser::is_rdp_port(tcp_info.dst_port) {
                            if let Some(rdp_info) = rdp_parser::parse_rdp(payload) {
                                if rdp_parser::is_suspicious_rdp(&rdp_info) {
                                    let event = OcsfNetworkEvent::traffic(
                                        device_clone.clone(),
                                        src_ip,
                                        tcp_info.src_port,
                                        dst_ip,
                                        tcp_info.dst_port,
                                        "RDP",
                                        3, // Medium severity
                                    );
                                    let _ = evt_tx_clone.send(event).await;
                                }
                            }
                        }

                        // Protocol anomaly detection on TCP payloads.
                        if let Some(alert) = proto_detector.check_payload(payload, tcp_info.dst_port) {
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
                }

                IpNextHeaderProtocols::Udp => {
                    let udp_data = transport_data.as_slice();
                    let udp_info = match udp::parse_udp(udp_data) {
                        Some(u) => u,
                        None => continue,
                    };

                    // DNS parsing on port 53 (DNS) and 5353 (mDNS).
                    let udp_payload = udp::extract_payload(udp_data);
                    if udp::is_dns_port(&udp_info) {
                        if let Some(dns_info) = dns::parse_dns(udp_payload) {
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

                    // Protocol anomaly detection on UDP payloads.
                    if let Some(alert) = proto_detector.check_payload(udp_payload, udp_info.dst_port) {
                        let event = OcsfNetworkEvent::from_alert(
                            device_clone.clone(),
                            src_ip,
                            udp_info.src_port,
                            dst_ip,
                            udp_info.dst_port,
                            "UDP",
                            &alert,
                        );
                        let _ = evt_tx_clone.send(event).await;
                    }

                    // C2 beacon detection on all UDP flows.
                    if let Some(alert) = c2_detector.record_packet(
                        &src_ip.to_string(),
                        &dst_ip.to_string(),
                        udp_info.dst_port,
                    ) {
                        let event = OcsfNetworkEvent::from_alert(
                            device_clone.clone(),
                            src_ip,
                            udp_info.src_port,
                            dst_ip,
                            udp_info.dst_port,
                            "UDP",
                            &alert,
                        );
                        let _ = evt_tx_clone.send(event).await;
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

    // Signal health server to stop.
    let _ = health_shutdown_tx.send(true);

    // Drop the event sender to close the transport channel.
    drop(evt_tx);

    // Cancel capture.
    capture_handle.abort();

    // Wait for processing and transport to drain.
    let _ = tokio::time::timeout(Duration::from_secs(5), processing_handle).await;
    let _ = tokio::time::timeout(Duration::from_secs(3), transport_handle).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), health_handle).await;

    info!("MxWatch agent stopped");
    Ok(())
}
