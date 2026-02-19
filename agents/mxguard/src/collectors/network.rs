//! Network connection collector.
//!
//! Periodically reads `/proc/net/tcp` (and `/proc/net/tcp6`) to enumerate
//! active TCP connections and emits OCSF Network Activity (class_uid 4001)
//! events for newly observed connections.

use std::collections::HashSet;
use std::fs;
use std::net::Ipv4Addr;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};

use crate::collectors::Collector;
use crate::config::NetworkCollectorConfig;
use crate::events::ocsf::{
    NetworkActivityData, OcsfDevice, OcsfEvent, OcsfSeverity,
};

/// A unique key for a TCP connection tuple.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ConnKey {
    local_addr: String,
    local_port: u16,
    remote_addr: String,
    remote_port: u16,
}

/// Collector that monitors TCP connections from procfs.
pub struct NetworkCollector {
    config: NetworkCollectorConfig,
    device: OcsfDevice,
}

impl NetworkCollector {
    pub fn new(config: &NetworkCollectorConfig, device: OcsfDevice) -> Self {
        Self {
            config: config.clone(),
            device,
        }
    }
}

#[async_trait]
impl Collector for NetworkCollector {
    fn name(&self) -> &'static str {
        "network"
    }

    async fn run(
        &self,
        tx: mpsc::Sender<OcsfEvent>,
        mut shutdown: watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        info!(
            "Network collector started (interval={}ms)",
            self.config.scan_interval_ms
        );
        let interval = Duration::from_millis(self.config.scan_interval_ms);
        let mut known_conns: HashSet<ConnKey> = HashSet::new();

        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = shutdown.changed() => {
                    info!("Network collector shutting down");
                    return Ok(());
                }
            }

            let current_conns = match parse_proc_net_tcp("/proc/net/tcp") {
                Ok(conns) => conns,
                Err(e) => {
                    warn!("Failed to parse /proc/net/tcp: {e}");
                    continue;
                }
            };

            for conn in &current_conns {
                let key = ConnKey {
                    local_addr: conn.local_addr.clone(),
                    local_port: conn.local_port,
                    remote_addr: conn.remote_addr.clone(),
                    remote_port: conn.remote_port,
                };

                if known_conns.contains(&key) {
                    continue;
                }
                known_conns.insert(key);

                // Skip loopback and listening sockets.
                if conn.remote_addr == "0.0.0.0" && conn.remote_port == 0 {
                    continue;
                }

                let severity = classify_connection_severity(conn);

                let event = OcsfEvent::network_activity(
                    self.device.clone(),
                    "Connect",
                    1,
                    severity,
                    conn.clone(),
                );

                if tx.send(event).await.is_err() {
                    debug!("Event channel closed, stopping network collector");
                    return Ok(());
                }
            }

            // Prune connections that are no longer present.
            let current_set: HashSet<ConnKey> = current_conns
                .iter()
                .map(|c| ConnKey {
                    local_addr: c.local_addr.clone(),
                    local_port: c.local_port,
                    remote_addr: c.remote_addr.clone(),
                    remote_port: c.remote_port,
                })
                .collect();
            known_conns.retain(|k| current_set.contains(k));
        }
    }
}

// ---------------------------------------------------------------------------
// /proc/net/tcp parser
// ---------------------------------------------------------------------------

/// Parse `/proc/net/tcp` into a list of connection records.
///
/// Each line (after the header) looks like:
/// ```text
///   sl  local_address rem_address   st tx_queue rx_queue ...
///    0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 ...
/// ```
fn parse_proc_net_tcp(path: &str) -> anyhow::Result<Vec<NetworkActivityData>> {
    let content = fs::read_to_string(path)?;
    let mut results = Vec::new();

    for line in content.lines().skip(1) {
        // Skip the header line.
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }

        let local = parse_addr_port(parts[1]);
        let remote = parse_addr_port(parts[2]);
        let state_hex = parts[3];

        let (local_addr, local_port) = match local {
            Some(v) => v,
            None => continue,
        };
        let (remote_addr, remote_port) = match remote {
            Some(v) => v,
            None => continue,
        };

        let state = tcp_state_name(state_hex);

        results.push(NetworkActivityData {
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            protocol: "TCP".into(),
            state,
            pid: None, // PID association requires reading /proc/<pid>/fd — left as TODO.
        });
    }

    Ok(results)
}

/// Parse a hex-encoded `addr:port` pair from /proc/net/tcp.
/// Example: `0100007F:1F90` -> ("127.0.0.1", 8080)
fn parse_addr_port(s: &str) -> Option<(String, u16)> {
    let mut parts = s.split(':');
    let addr_hex = parts.next()?;
    let port_hex = parts.next()?;

    let addr_u32 = u32::from_str_radix(addr_hex, 16).ok()?;
    let _ip = Ipv4Addr::from(addr_u32.to_be());
    // /proc/net/tcp stores the address in host byte order on little-endian,
    // so the octets are already reversed. We just reconstruct.
    let octets = addr_u32.to_le_bytes();
    let ip_str = format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]);

    let port = u16::from_str_radix(port_hex, 16).ok()?;

    Some((ip_str, port))
}

fn tcp_state_name(hex: &str) -> String {
    match hex {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        _ => "UNKNOWN",
    }
    .into()
}

/// Simple heuristic severity classification for new connections.
fn classify_connection_severity(conn: &NetworkActivityData) -> OcsfSeverity {
    // High-value destination ports that are commonly abused.
    let suspicious_ports: &[u16] = &[4444, 5555, 6666, 8888, 1337, 31337];
    if suspicious_ports.contains(&conn.remote_port) {
        return OcsfSeverity::High;
    }

    // External ESTABLISHED connections to uncommon ports.
    if conn.state == "ESTABLISHED" && conn.remote_port > 10000 {
        return OcsfSeverity::Medium;
    }

    OcsfSeverity::Informational
}
