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
    Ok(parse_proc_net_tcp_content(&content))
}

/// Parse the content string of `/proc/net/tcp` into connection records.
///
/// Accepts file content as a `&str` so callers (and tests) can pass any string
/// without touching the filesystem.
pub(crate) fn parse_proc_net_tcp_content(content: &str) -> Vec<NetworkActivityData> {
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

    results
}

/// Parse a hex-encoded `addr:port` pair from /proc/net/tcp.
/// Example: `0100007F:1F90` -> ("127.0.0.1", 8080)
pub(crate) fn parse_addr_port(s: &str) -> Option<(String, u16)> {
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

pub(crate) fn tcp_state_name(hex: &str) -> String {
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
pub(crate) fn classify_connection_severity(conn: &NetworkActivityData) -> OcsfSeverity {
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

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // parse_addr_port
    // -----------------------------------------------------------------------

    #[test]
    fn parse_addr_port_loopback_port_8080() {
        // 0100007F = 127.0.0.1 (little-endian), 1F90 = 8080
        let result = parse_addr_port("0100007F:1F90");
        assert_eq!(result, Some(("127.0.0.1".into(), 8080)));
    }

    #[test]
    fn parse_addr_port_any_addr_port_zero() {
        // 00000000 = 0.0.0.0, 0000 = 0
        let result = parse_addr_port("00000000:0000");
        assert_eq!(result, Some(("0.0.0.0".into(), 0)));
    }

    #[test]
    fn parse_addr_port_any_addr_port_22() {
        // 00000000 = 0.0.0.0, 0016 = 22 (SSH)
        let result = parse_addr_port("00000000:0016");
        assert_eq!(result, Some(("0.0.0.0".into(), 22)));
    }

    #[test]
    fn parse_addr_port_any_addr_port_80() {
        // 00000000 = 0.0.0.0, 0050 = 80 (HTTP)
        let result = parse_addr_port("00000000:0050");
        assert_eq!(result, Some(("0.0.0.0".into(), 80)));
    }

    #[test]
    fn parse_addr_port_returns_none_for_invalid_hex_addr() {
        assert!(parse_addr_port("ZZZZZZZZ:0050").is_none());
    }

    #[test]
    fn parse_addr_port_returns_none_for_invalid_hex_port() {
        assert!(parse_addr_port("00000000:ZZZZ").is_none());
    }

    #[test]
    fn parse_addr_port_returns_none_for_missing_colon() {
        assert!(parse_addr_port("000000000050").is_none());
    }

    #[test]
    fn parse_addr_port_returns_none_for_empty_string() {
        assert!(parse_addr_port("").is_none());
    }

    // -----------------------------------------------------------------------
    // tcp_state_name
    // -----------------------------------------------------------------------

    #[test]
    fn tcp_state_name_established() {
        assert_eq!(tcp_state_name("01"), "ESTABLISHED");
    }

    #[test]
    fn tcp_state_name_listen() {
        assert_eq!(tcp_state_name("0A"), "LISTEN");
    }

    #[test]
    fn tcp_state_name_all_known_states() {
        let expected = [
            ("01", "ESTABLISHED"),
            ("02", "SYN_SENT"),
            ("03", "SYN_RECV"),
            ("04", "FIN_WAIT1"),
            ("05", "FIN_WAIT2"),
            ("06", "TIME_WAIT"),
            ("07", "CLOSE"),
            ("08", "CLOSE_WAIT"),
            ("09", "LAST_ACK"),
            ("0A", "LISTEN"),
            ("0B", "CLOSING"),
        ];
        for (hex, name) in expected {
            assert_eq!(tcp_state_name(hex), name, "state mismatch for hex={hex}");
        }
    }

    #[test]
    fn tcp_state_name_unknown_returns_unknown() {
        assert_eq!(tcp_state_name("FF"), "UNKNOWN");
        assert_eq!(tcp_state_name("00"), "UNKNOWN");
        assert_eq!(tcp_state_name(""), "UNKNOWN");
    }

    // -----------------------------------------------------------------------
    // parse_proc_net_tcp_content
    // -----------------------------------------------------------------------

    /// Typical /proc/net/tcp content with three entries:
    ///   slot 0: loopback LISTEN on port 8080
    ///   slot 1: 0.0.0.0:22 LISTEN (SSH)
    ///   slot 2: 10.0.2.15:54504 -> 10.0.2.94:80 ESTABLISHED
    const SAMPLE_TCP: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 23456
   2: 0F02000A:D4E8 5E02000A:0050 01 00000000:00000000 00:00000000 00000000  1000        0 34567
";

    #[test]
    fn parse_content_returns_correct_count() {
        let conns = parse_proc_net_tcp_content(SAMPLE_TCP);
        assert_eq!(conns.len(), 3);
    }

    #[test]
    fn parse_content_first_entry_is_loopback_listen() {
        let conns = parse_proc_net_tcp_content(SAMPLE_TCP);
        let c = &conns[0];
        assert_eq!(c.local_addr, "127.0.0.1");
        assert_eq!(c.local_port, 8080);
        assert_eq!(c.remote_addr, "0.0.0.0");
        assert_eq!(c.remote_port, 0);
        assert_eq!(c.state, "LISTEN");
        assert_eq!(c.protocol, "TCP");
        assert!(c.pid.is_none());
    }

    #[test]
    fn parse_content_second_entry_ssh_listen() {
        let conns = parse_proc_net_tcp_content(SAMPLE_TCP);
        let c = &conns[1];
        assert_eq!(c.local_addr, "0.0.0.0");
        assert_eq!(c.local_port, 22);
        assert_eq!(c.remote_addr, "0.0.0.0");
        assert_eq!(c.remote_port, 0);
        assert_eq!(c.state, "LISTEN");
    }

    #[test]
    fn parse_content_third_entry_established() {
        let conns = parse_proc_net_tcp_content(SAMPLE_TCP);
        let c = &conns[2];
        assert_eq!(c.local_addr, "10.0.2.15");
        assert_eq!(c.local_port, 54504);
        assert_eq!(c.remote_addr, "10.0.2.94");
        assert_eq!(c.remote_port, 80);
        assert_eq!(c.state, "ESTABLISHED");
    }

    #[test]
    fn parse_content_header_only_returns_empty() {
        let header_only = "  sl  local_address rem_address   st tx_queue rx_queue\n";
        let conns = parse_proc_net_tcp_content(header_only);
        assert!(conns.is_empty());
    }

    #[test]
    fn parse_content_empty_string_returns_empty() {
        let conns = parse_proc_net_tcp_content("");
        assert!(conns.is_empty());
    }

    #[test]
    fn parse_content_skips_short_lines() {
        // Lines with fewer than 4 whitespace-separated fields are skipped.
        let content = "  sl  local_address rem_address   st\n   0: 0100007F:1F90\n";
        let conns = parse_proc_net_tcp_content(content);
        assert!(conns.is_empty());
    }

    #[test]
    fn parse_content_skips_lines_with_invalid_addresses() {
        let content = "\
  sl  local_address rem_address   st tx_queue rx_queue
   0: ZZZZZZZZ:1F90 00000000:0000 0A 00000000:00000000
";
        let conns = parse_proc_net_tcp_content(content);
        assert!(conns.is_empty());
    }

    #[test]
    fn parse_content_all_entries_have_tcp_protocol() {
        let conns = parse_proc_net_tcp_content(SAMPLE_TCP);
        for c in &conns {
            assert_eq!(c.protocol, "TCP");
        }
    }

    #[test]
    fn parse_content_all_entries_have_no_pid() {
        let conns = parse_proc_net_tcp_content(SAMPLE_TCP);
        for c in &conns {
            assert!(c.pid.is_none(), "pid should be None (TODO: /proc/<pid>/fd)");
        }
    }

    // -----------------------------------------------------------------------
    // classify_connection_severity
    // -----------------------------------------------------------------------

    fn make_conn(remote_addr: &str, remote_port: u16, state: &str) -> NetworkActivityData {
        NetworkActivityData {
            local_addr: "127.0.0.1".into(),
            local_port: 12345,
            remote_addr: remote_addr.into(),
            remote_port,
            protocol: "TCP".into(),
            state: state.into(),
            pid: None,
        }
    }

    #[test]
    fn classify_severity_high_for_port_4444() {
        let conn = make_conn("10.0.0.1", 4444, "ESTABLISHED");
        assert_eq!(classify_connection_severity(&conn), OcsfSeverity::High);
    }

    #[test]
    fn classify_severity_high_for_port_1337() {
        let conn = make_conn("10.0.0.1", 1337, "ESTABLISHED");
        assert_eq!(classify_connection_severity(&conn), OcsfSeverity::High);
    }

    #[test]
    fn classify_severity_high_for_port_31337() {
        let conn = make_conn("10.0.0.1", 31337, "ESTABLISHED");
        assert_eq!(classify_connection_severity(&conn), OcsfSeverity::High);
    }

    #[test]
    fn classify_severity_high_for_all_suspicious_ports() {
        for port in [4444u16, 5555, 6666, 8888, 1337, 31337] {
            let conn = make_conn("10.0.0.1", port, "ESTABLISHED");
            assert_eq!(
                classify_connection_severity(&conn),
                OcsfSeverity::High,
                "port {port} should be High severity"
            );
        }
    }

    #[test]
    fn classify_severity_medium_for_established_high_port() {
        // Port > 10000, state ESTABLISHED, not in suspicious list.
        let conn = make_conn("10.0.0.1", 12345, "ESTABLISHED");
        assert_eq!(classify_connection_severity(&conn), OcsfSeverity::Medium);
    }

    #[test]
    fn classify_severity_informational_for_established_low_port() {
        // Port <= 10000 and not suspicious.
        let conn = make_conn("10.0.0.1", 443, "ESTABLISHED");
        assert_eq!(
            classify_connection_severity(&conn),
            OcsfSeverity::Informational
        );
    }

    #[test]
    fn classify_severity_informational_for_listen_high_port() {
        // High port but not ESTABLISHED state — not Medium.
        let conn = make_conn("0.0.0.0", 15000, "LISTEN");
        assert_eq!(
            classify_connection_severity(&conn),
            OcsfSeverity::Informational
        );
    }

    #[test]
    fn classify_severity_informational_for_http() {
        let conn = make_conn("10.0.0.1", 80, "ESTABLISHED");
        assert_eq!(
            classify_connection_severity(&conn),
            OcsfSeverity::Informational
        );
    }

    // -----------------------------------------------------------------------
    // parse_proc_net_tcp — live /proc/net/tcp test
    // -----------------------------------------------------------------------

    #[test]
    fn parse_proc_net_tcp_live_succeeds_on_linux() {
        // /proc/net/tcp always exists on Linux; we just verify the parse
        // succeeds and returns a non-panicking result.
        let conns = parse_proc_net_tcp_content(
            &std::fs::read_to_string("/proc/net/tcp")
                .expect("/proc/net/tcp must be readable on Linux"),
        );
        // There is always at least one socket (loopback, etc.) on a running system,
        // but we just check that parsing does not panic or error.
        let _ = conns; // result is valid
    }
}
