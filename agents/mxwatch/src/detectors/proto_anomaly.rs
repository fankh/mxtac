//! Protocol anomaly detector — feature 25.11.
//!
//! Identifies traffic on known ports where the observed protocol does not
//! match the service expected on that port. Examples:
//!   - Plaintext HTTP on port 443 (expected TLS/HTTPS)
//!   - TLS traffic on port 80 (expected plaintext HTTP)
//!   - Non-DNS payload on port 53 (expected DNS)
//!   - SSH on a TLS service port (possible covert channel)
//!
//! The detector is **stateless** — it operates on single TCP/UDP payloads
//! without tracking session history. Protocol identification uses lightweight
//! byte-level signature matching: no full protocol parsing is performed.

use tracing::debug;

use crate::config::ProtoAnomalyDetectorConfig;
use crate::detectors::{Alert, AlertSeverity};

// ---------------------------------------------------------------------------
// Protocol kind
// ---------------------------------------------------------------------------

/// Protocols identifiable from payload signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolKind {
    /// HTTP/1.x (plaintext): methods (`GET`, `POST`, …) or `HTTP/` status line.
    Http,
    /// TLS 1.0–1.3 record layer (all content types: handshake, app-data, …).
    Tls,
    /// SSH protocol banner (`SSH-`).
    Ssh,
    /// SMTP greeting (`220 `) or client command (`EHLO`, `HELO`).
    Smtp,
    /// FTP control channel banner (`220 `) or command (`USER`, `PASS`).
    Ftp,
    /// DNS wire format (heuristic: message-ID + valid flags + ≥1 question).
    Dns,
}

impl ProtocolKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Http => "HTTP",
            Self::Tls => "TLS",
            Self::Ssh => "SSH",
            Self::Smtp => "SMTP",
            Self::Ftp => "FTP",
            Self::Dns => "DNS",
        }
    }
}

// ---------------------------------------------------------------------------
// Port-to-protocol expectation table
// ---------------------------------------------------------------------------

/// Return the protocol expected on `port`, or `None` for unknown/dynamic ports.
///
/// The table covers IANA well-known ports for the protocols we can fingerprint.
fn expected_protocol(port: u16) -> Option<ProtocolKind> {
    match port {
        // Plaintext HTTP (also 8000, 8008, 8080, 8888 common proxies/devservers)
        80 | 8000 | 8008 | 8080 | 8888 => Some(ProtocolKind::Http),
        // TLS-wrapped services: HTTPS, SMTPS, LDAPS, DoT, IMAPS, POP3S, AMQPS, HTTPS-Alt
        443 | 465 | 636 | 853 | 993 | 995 | 5671 | 8443 => Some(ProtocolKind::Tls),
        // SSH
        22 => Some(ProtocolKind::Ssh),
        // SMTP (plaintext + STARTTLS)
        25 | 587 => Some(ProtocolKind::Smtp),
        // FTP control
        21 => Some(ProtocolKind::Ftp),
        // DNS (UDP 53 + mDNS 5353 + DNS-over-TCP 53)
        53 | 5353 => Some(ProtocolKind::Dns),
        _ => None,
    }
}

/// Return `true` for ports where we alert even on *unrecognized* payloads
/// (i.e. the expected protocol is well-defined and anything else is suspicious).
fn is_strict_port(port: u16) -> bool {
    matches!(port, 443 | 22 | 53 | 5353 | 465 | 636 | 853 | 993 | 995)
}

// ---------------------------------------------------------------------------
// Payload-level protocol fingerprinting
// ---------------------------------------------------------------------------

/// Attempt to identify the protocol carried in `payload`.
///
/// Returns `None` when the payload is too short or does not match any known
/// signature.  The check is deliberately cheap — no allocations, no parsing
/// beyond the first ≤ 20 bytes.
pub fn detect_protocol(payload: &[u8]) -> Option<ProtocolKind> {
    if is_tls_payload(payload) {
        return Some(ProtocolKind::Tls);
    }
    if is_http_payload(payload) {
        return Some(ProtocolKind::Http);
    }
    if is_ssh_payload(payload) {
        return Some(ProtocolKind::Ssh);
    }
    if is_smtp_payload(payload) {
        return Some(ProtocolKind::Smtp);
    }
    if is_ftp_payload(payload) {
        return Some(ProtocolKind::Ftp);
    }
    if is_dns_payload(payload) {
        return Some(ProtocolKind::Dns);
    }
    None
}

/// TLS record signature: content_type ∈ [20, 24], major version byte = 0x03.
///
/// This matches all TLS 1.0–1.3 and SSL 3.0 record types.  The version_major
/// byte is always 0x03 on the wire even for TLS 1.3 (RFC 8446 §5.1).
fn is_tls_payload(payload: &[u8]) -> bool {
    if payload.len() < 3 {
        return false;
    }
    matches!(payload[0], 20..=24) && payload[1] == 0x03
}

/// HTTP/1.x request or response: common method tokens or `HTTP/` status line.
fn is_http_payload(payload: &[u8]) -> bool {
    // Examine only the first 16 bytes to keep this cheap.
    let prefix = &payload[..payload.len().min(16)];
    let Ok(text) = std::str::from_utf8(prefix) else {
        return false;
    };
    // Request methods
    for method in &["GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "] {
        if text.starts_with(method) {
            return true;
        }
    }
    // Response status line
    text.starts_with("HTTP/")
}

/// SSH protocol version exchange banner (RFC 4253 §4.2): `SSH-<digit>`.
fn is_ssh_payload(payload: &[u8]) -> bool {
    payload.starts_with(b"SSH-")
}

/// SMTP server greeting (`220 `) or common client commands.
///
/// `220 ` is the "Service ready" response from an SMTP server (RFC 5321 §4.2).
/// `EHLO` / `HELO` are the standard client handshake commands.
fn is_smtp_payload(payload: &[u8]) -> bool {
    payload.starts_with(b"220 ")
        || payload.starts_with(b"EHLO")
        || payload.starts_with(b"HELO")
        || payload.starts_with(b"MAIL FROM")
}

/// FTP control channel banner or common commands.
fn is_ftp_payload(payload: &[u8]) -> bool {
    // FTP server greeting reuses "220 " like SMTP.  Disambiguate later only if
    // both appear on the same port — for now, SMTP takes priority.
    payload.starts_with(b"USER ")
        || payload.starts_with(b"PASS ")
        || payload.starts_with(b"LIST")
        || payload.starts_with(b"RETR ")
}

/// DNS wire-format heuristic: minimum 12-byte header with sensible flags.
///
/// A minimal DNS message header is:
///   transaction_id (2) + flags (2) + qdcount (2) + ancount (2) +
///   nscount (2) + arcount (2) = 12 bytes
///
/// We check:
///   - Message is at least 12 bytes
///   - QR bit (flags bit 15) is 0 (query) or 1 (response) — always valid
///   - Opcode (flags bits 14–11) is 0 (QUERY) or 1 (IQUERY) or 2 (STATUS)
///   - QDCOUNT > 0 (at least one question)
pub fn is_dns_payload(payload: &[u8]) -> bool {
    if payload.len() < 12 {
        return false;
    }
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let opcode = (flags >> 11) & 0x0F;
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    // Opcode 0 (QUERY), 1 (IQUERY), 2 (STATUS), 4 (NOTIFY), 5 (UPDATE)
    opcode <= 5 && qdcount > 0
}

// ---------------------------------------------------------------------------
// Detector
// ---------------------------------------------------------------------------

/// Stateless protocol-anomaly detector.
pub struct ProtoAnomalyDetector {
    config: ProtoAnomalyDetectorConfig,
}

impl ProtoAnomalyDetector {
    pub fn new(config: &ProtoAnomalyDetectorConfig) -> Self {
        Self { config: config.clone() }
    }

    /// Inspect `payload` arriving on `dst_port` for protocol mismatches.
    ///
    /// Returns an [`Alert`] when:
    /// - A recognizable protocol is detected that conflicts with what `dst_port`
    ///   is supposed to carry (e.g. HTTP on port 443).
    /// - The payload on a strict port (443, 22, 53, …) cannot be matched to
    ///   any known protocol signature.
    ///
    /// Returns `None` when:
    /// - `payload` is empty.
    /// - `dst_port` is not in the known-port table.
    /// - The detected protocol matches the expected one.
    pub fn check_payload(&self, payload: &[u8], dst_port: u16) -> Option<Alert> {
        if payload.is_empty() {
            return None;
        }

        // Only check ports we have expectations for.
        let expected = expected_protocol(dst_port)?;
        let observed = detect_protocol(payload);

        match observed {
            Some(observed_kind) if observed_kind == expected => {
                // Traffic matches expectations — no alert.
                None
            }
            Some(observed_kind) => {
                // Known, mismatched protocol.
                debug!(
                    "Proto anomaly on port {}: expected {}, observed {}",
                    dst_port,
                    expected.as_str(),
                    observed_kind.as_str(),
                );
                Some(Alert {
                    detector: "proto_anomaly".into(),
                    severity: AlertSeverity::High,
                    description: format!(
                        "Protocol anomaly on port {dst_port}: expected {} but detected {}",
                        expected.as_str(),
                        observed_kind.as_str(),
                    ),
                    evidence: serde_json::json!({
                        "port": dst_port,
                        "expected_protocol": expected.as_str(),
                        "observed_protocol": observed_kind.as_str(),
                    }),
                })
            }
            None if is_strict_port(dst_port) => {
                // Unrecognized payload on a port with a strict expectation.
                debug!(
                    "Proto anomaly on port {}: expected {}, unrecognized payload",
                    dst_port,
                    expected.as_str(),
                );
                Some(Alert {
                    detector: "proto_anomaly".into(),
                    severity: AlertSeverity::Medium,
                    description: format!(
                        "Unrecognized protocol on port {dst_port} (expected {})",
                        expected.as_str(),
                    ),
                    evidence: serde_json::json!({
                        "port": dst_port,
                        "expected_protocol": expected.as_str(),
                        "observed_protocol": null,
                        "reason": "unrecognized_payload",
                    }),
                })
            }
            None => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProtoAnomalyDetectorConfig;
    use crate::detectors::AlertSeverity;

    fn make_detector() -> ProtoAnomalyDetector {
        ProtoAnomalyDetector::new(&ProtoAnomalyDetectorConfig { enabled: true })
    }

    // -----------------------------------------------------------------------
    // is_tls_payload
    // -----------------------------------------------------------------------

    #[test]
    fn test_tls_payload_handshake_record() {
        // content_type=22 (Handshake), major=3, minor=3 (TLS 1.2 record layer)
        let pkt = [0x16u8, 0x03, 0x03, 0x00, 0x40];
        assert!(is_tls_payload(&pkt));
    }

    #[test]
    fn test_tls_payload_application_data_record() {
        // content_type=23 (ApplicationData)
        let pkt = [0x17u8, 0x03, 0x03, 0x00, 0x20];
        assert!(is_tls_payload(&pkt));
    }

    #[test]
    fn test_tls_payload_change_cipher_spec() {
        // content_type=20 (ChangeCipherSpec)
        let pkt = [0x14u8, 0x03, 0x03, 0x00, 0x01];
        assert!(is_tls_payload(&pkt));
    }

    #[test]
    fn test_tls_payload_alert_record() {
        // content_type=21 (Alert)
        let pkt = [0x15u8, 0x03, 0x01, 0x00, 0x02];
        assert!(is_tls_payload(&pkt));
    }

    #[test]
    fn test_tls_payload_wrong_version_major() {
        // major=0x02 (not a TLS record we recognise)
        let pkt = [0x16u8, 0x02, 0x00, 0x00, 0x10];
        assert!(!is_tls_payload(&pkt));
    }

    #[test]
    fn test_tls_payload_wrong_content_type() {
        // content_type=0x80 (not in 20–24)
        let pkt = [0x80u8, 0x03, 0x03, 0x00, 0x10];
        assert!(!is_tls_payload(&pkt));
    }

    #[test]
    fn test_tls_payload_too_short() {
        assert!(!is_tls_payload(&[0x16u8, 0x03]));
        assert!(!is_tls_payload(&[]));
    }

    // -----------------------------------------------------------------------
    // is_http_payload
    // -----------------------------------------------------------------------

    #[test]
    fn test_http_payload_get_request() {
        assert!(is_http_payload(b"GET / HTTP/1.1\r\nHost: x.com\r\n\r\n"));
    }

    #[test]
    fn test_http_payload_post_request() {
        assert!(is_http_payload(b"POST /api HTTP/1.1\r\n"));
    }

    #[test]
    fn test_http_payload_response() {
        assert!(is_http_payload(b"HTTP/1.1 200 OK\r\n"));
    }

    #[test]
    fn test_http_payload_all_methods() {
        for method in &["GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "] {
            let pkt = format!("{method}/ HTTP/1.1\r\n").into_bytes();
            assert!(is_http_payload(&pkt), "method {method} not detected");
        }
    }

    #[test]
    fn test_http_payload_non_http() {
        assert!(!is_http_payload(b"\x16\x03\x03\x00\x40"));
        assert!(!is_http_payload(b"SSH-2.0-OpenSSH_8.9\r\n"));
        assert!(!is_http_payload(b"220 mail.example.com ESMTP\r\n"));
    }

    // -----------------------------------------------------------------------
    // is_ssh_payload
    // -----------------------------------------------------------------------

    #[test]
    fn test_ssh_payload_banner() {
        assert!(is_ssh_payload(b"SSH-2.0-OpenSSH_8.9p1\r\n"));
        assert!(is_ssh_payload(b"SSH-1.99-OpenSSH_4.3\r\n"));
    }

    #[test]
    fn test_ssh_payload_not_ssh() {
        assert!(!is_ssh_payload(b"GET / HTTP/1.1\r\n"));
        assert!(!is_ssh_payload(b"\x16\x03\x01\x00\x80"));
    }

    // -----------------------------------------------------------------------
    // is_smtp_payload
    // -----------------------------------------------------------------------

    #[test]
    fn test_smtp_payload_greeting() {
        assert!(is_smtp_payload(b"220 mail.example.com ESMTP Postfix\r\n"));
    }

    #[test]
    fn test_smtp_payload_ehlo() {
        assert!(is_smtp_payload(b"EHLO client.example.com\r\n"));
    }

    #[test]
    fn test_smtp_payload_helo() {
        assert!(is_smtp_payload(b"HELO client.example.com\r\n"));
    }

    #[test]
    fn test_smtp_payload_mail_from() {
        assert!(is_smtp_payload(b"MAIL FROM:<user@example.com>\r\n"));
    }

    #[test]
    fn test_smtp_payload_not_smtp() {
        assert!(!is_smtp_payload(b"GET / HTTP/1.1\r\n"));
        assert!(!is_smtp_payload(b"SSH-2.0-OpenSSH\r\n"));
    }

    // -----------------------------------------------------------------------
    // is_dns_payload
    // -----------------------------------------------------------------------

    #[test]
    fn test_dns_payload_valid_query() {
        // A minimal DNS query: txid=0x1234, flags=0x0100 (standard query),
        // qdcount=1, ancount=0, nscount=0, arcount=0
        let pkt = [
            0x12u8, 0x34, // transaction ID
            0x01, 0x00,   // flags: RD=1 (recursion desired), standard query
            0x00, 0x01,   // QDCOUNT = 1
            0x00, 0x00,   // ANCOUNT = 0
            0x00, 0x00,   // NSCOUNT = 0
            0x00, 0x00,   // ARCOUNT = 0
        ];
        assert!(is_dns_payload(&pkt));
    }

    #[test]
    fn test_dns_payload_valid_response() {
        // DNS response: QR=1, qdcount=1, ancount=1
        let pkt = [
            0x12u8, 0x34,
            0x81, 0x80, // flags: QR=1, RD=1, RA=1
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x01, // ANCOUNT = 1
            0x00, 0x00,
            0x00, 0x00,
        ];
        assert!(is_dns_payload(&pkt));
    }

    #[test]
    fn test_dns_payload_too_short() {
        assert!(!is_dns_payload(&[0x12u8, 0x34, 0x01, 0x00, 0x00, 0x01]));
        assert!(!is_dns_payload(&[]));
    }

    #[test]
    fn test_dns_payload_zero_qdcount() {
        // qdcount = 0 → likely not a DNS query (or empty message)
        let pkt = [
            0x12u8, 0x34,
            0x01, 0x00,
            0x00, 0x00, // QDCOUNT = 0
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,
        ];
        assert!(!is_dns_payload(&pkt));
    }

    #[test]
    fn test_dns_payload_invalid_opcode() {
        // Opcode = 15 (reserved) → reject
        let pkt = [
            0x12u8, 0x34,
            0x78, 0x00, // flags: opcode=0xF (15)
            0x00, 0x01,
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,
        ];
        assert!(!is_dns_payload(&pkt));
    }

    // -----------------------------------------------------------------------
    // detect_protocol
    // -----------------------------------------------------------------------

    #[test]
    fn test_detect_protocol_tls() {
        let pkt = [0x16u8, 0x03, 0x03, 0x00, 0x40];
        assert_eq!(detect_protocol(&pkt), Some(ProtocolKind::Tls));
    }

    #[test]
    fn test_detect_protocol_http() {
        assert_eq!(
            detect_protocol(b"GET / HTTP/1.1\r\n"),
            Some(ProtocolKind::Http)
        );
    }

    #[test]
    fn test_detect_protocol_ssh() {
        assert_eq!(
            detect_protocol(b"SSH-2.0-OpenSSH_8.9\r\n"),
            Some(ProtocolKind::Ssh)
        );
    }

    #[test]
    fn test_detect_protocol_smtp() {
        assert_eq!(
            detect_protocol(b"220 mail.example.com ESMTP\r\n"),
            Some(ProtocolKind::Smtp)
        );
    }

    #[test]
    fn test_detect_protocol_unknown() {
        // Binary garbage that doesn't match any signature.
        assert_eq!(
            detect_protocol(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00]),
            None
        );
    }

    #[test]
    fn test_detect_protocol_empty() {
        assert_eq!(detect_protocol(&[]), None);
    }

    // -----------------------------------------------------------------------
    // ProtoAnomalyDetector::check_payload — normal traffic (no alert)
    // -----------------------------------------------------------------------

    #[test]
    fn test_no_alert_tls_on_443() {
        let det = make_detector();
        let tls_pkt = [0x16u8, 0x03, 0x03, 0x00, 0x40];
        assert!(det.check_payload(&tls_pkt, 443).is_none());
    }

    #[test]
    fn test_no_alert_http_on_80() {
        let det = make_detector();
        assert!(det.check_payload(b"GET / HTTP/1.1\r\n", 80).is_none());
    }

    #[test]
    fn test_no_alert_ssh_on_22() {
        let det = make_detector();
        assert!(det.check_payload(b"SSH-2.0-OpenSSH_8.9\r\n", 22).is_none());
    }

    #[test]
    fn test_no_alert_smtp_on_25() {
        let det = make_detector();
        assert!(det.check_payload(b"220 mail.example.com ESMTP\r\n", 25).is_none());
    }

    #[test]
    fn test_no_alert_unknown_port() {
        let det = make_detector();
        // Port 12345 is not in the expectation table — no alert regardless of payload.
        let tls_pkt = [0x16u8, 0x03, 0x03, 0x00, 0x40];
        assert!(det.check_payload(&tls_pkt, 12345).is_none());
    }

    #[test]
    fn test_no_alert_empty_payload() {
        let det = make_detector();
        assert!(det.check_payload(&[], 443).is_none());
    }

    // -----------------------------------------------------------------------
    // ProtoAnomalyDetector::check_payload — mismatched protocol (alert)
    // -----------------------------------------------------------------------

    #[test]
    fn test_alert_http_on_443() {
        let det = make_detector();
        let alert = det.check_payload(b"GET / HTTP/1.1\r\nHost: x.com\r\n\r\n", 443);
        assert!(alert.is_some(), "expected alert for HTTP on port 443");
        let alert = alert.unwrap();
        assert_eq!(alert.detector, "proto_anomaly");
        assert_eq!(alert.severity, AlertSeverity::High);
        assert!(alert.description.contains("443"));
        assert!(alert.description.contains("HTTP"));
        assert!(alert.description.contains("TLS"));
    }

    #[test]
    fn test_alert_tls_on_80() {
        let det = make_detector();
        let tls_pkt = [0x16u8, 0x03, 0x03, 0x00, 0x40];
        let alert = det.check_payload(&tls_pkt, 80);
        assert!(alert.is_some(), "expected alert for TLS on port 80");
        let alert = alert.unwrap();
        assert_eq!(alert.severity, AlertSeverity::High);
        assert!(alert.description.contains("80"));
        assert!(alert.description.contains("TLS"));
        assert!(alert.description.contains("HTTP"));
    }

    #[test]
    fn test_alert_ssh_on_443() {
        let det = make_detector();
        let alert = det.check_payload(b"SSH-2.0-OpenSSH_9.0\r\n", 443);
        assert!(alert.is_some(), "expected alert for SSH on port 443");
        let alert = alert.unwrap();
        assert_eq!(alert.severity, AlertSeverity::High);
        assert!(alert.description.contains("SSH"));
        assert!(alert.description.contains("TLS"));
    }

    #[test]
    fn test_alert_http_on_22() {
        let det = make_detector();
        let alert = det.check_payload(b"GET / HTTP/1.1\r\n", 22);
        assert!(alert.is_some(), "expected alert for HTTP on port 22 (SSH port)");
        let alert = alert.unwrap();
        assert_eq!(alert.severity, AlertSeverity::High);
    }

    #[test]
    fn test_alert_http_on_993() {
        // IMAPS (993) expects TLS; HTTP is anomalous.
        let det = make_detector();
        let alert = det.check_payload(b"GET / HTTP/1.1\r\n", 993);
        assert!(alert.is_some(), "expected alert for HTTP on IMAPS port 993");
        let alert = alert.unwrap();
        assert_eq!(alert.severity, AlertSeverity::High);
    }

    #[test]
    fn test_alert_tls_on_25() {
        // SMTP (25) expects plaintext SMTP; TLS is anomalous.
        let det = make_detector();
        let tls_pkt = [0x16u8, 0x03, 0x03, 0x00, 0x40];
        let alert = det.check_payload(&tls_pkt, 25);
        assert!(alert.is_some(), "expected alert for TLS on SMTP port 25");
        let alert = alert.unwrap();
        assert_eq!(alert.severity, AlertSeverity::High);
    }

    // -----------------------------------------------------------------------
    // ProtoAnomalyDetector::check_payload — unrecognized payload on strict ports
    // -----------------------------------------------------------------------

    #[test]
    fn test_alert_unrecognized_payload_on_443() {
        let det = make_detector();
        // Random binary data that matches no known signature.
        let alert = det.check_payload(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03], 443);
        assert!(
            alert.is_some(),
            "expected alert for unrecognized payload on strict port 443"
        );
        let alert = alert.unwrap();
        assert_eq!(alert.severity, AlertSeverity::Medium);
        assert!(alert.description.contains("443"));
    }

    #[test]
    fn test_alert_unrecognized_payload_on_22() {
        let det = make_detector();
        let alert = det.check_payload(&[0xFF, 0xFE, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05], 22);
        assert!(
            alert.is_some(),
            "expected alert for unrecognized payload on strict port 22"
        );
        let alert = alert.unwrap();
        assert_eq!(alert.severity, AlertSeverity::Medium);
    }

    #[test]
    fn test_no_alert_unrecognized_payload_on_non_strict_port() {
        let det = make_detector();
        // Port 80 is not a strict port — unrecognized payload is not alerted.
        let alert = det.check_payload(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03], 80);
        assert!(
            alert.is_none(),
            "port 80 is not strict — unrecognized payload should not alert"
        );
    }

    // -----------------------------------------------------------------------
    // Alert evidence fields
    // -----------------------------------------------------------------------

    #[test]
    fn test_alert_evidence_contains_port_and_protocols() {
        let det = make_detector();
        let alert = det
            .check_payload(b"GET / HTTP/1.1\r\nHost: x.com\r\n\r\n", 443)
            .unwrap();
        assert_eq!(alert.evidence["port"], 443);
        assert_eq!(alert.evidence["expected_protocol"], "TLS");
        assert_eq!(alert.evidence["observed_protocol"], "HTTP");
    }

    #[test]
    fn test_unrecognized_alert_evidence_has_null_observed() {
        let det = make_detector();
        let alert = det
            .check_payload(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03], 443)
            .unwrap();
        assert_eq!(alert.evidence["port"], 443);
        assert_eq!(alert.evidence["expected_protocol"], "TLS");
        assert!(alert.evidence["observed_protocol"].is_null());
    }

    // -----------------------------------------------------------------------
    // expected_protocol helper
    // -----------------------------------------------------------------------

    #[test]
    fn test_expected_protocol_http_ports() {
        for port in &[80u16, 8000, 8008, 8080, 8888] {
            assert_eq!(
                expected_protocol(*port),
                Some(ProtocolKind::Http),
                "port {port}"
            );
        }
    }

    #[test]
    fn test_expected_protocol_tls_ports() {
        for port in &[443u16, 465, 636, 853, 993, 995, 5671, 8443] {
            assert_eq!(
                expected_protocol(*port),
                Some(ProtocolKind::Tls),
                "port {port}"
            );
        }
    }

    #[test]
    fn test_expected_protocol_ssh() {
        assert_eq!(expected_protocol(22), Some(ProtocolKind::Ssh));
    }

    #[test]
    fn test_expected_protocol_dns() {
        assert_eq!(expected_protocol(53), Some(ProtocolKind::Dns));
        assert_eq!(expected_protocol(5353), Some(ProtocolKind::Dns));
    }

    #[test]
    fn test_expected_protocol_smtp() {
        assert_eq!(expected_protocol(25), Some(ProtocolKind::Smtp));
        assert_eq!(expected_protocol(587), Some(ProtocolKind::Smtp));
    }

    #[test]
    fn test_expected_protocol_unknown_port() {
        assert_eq!(expected_protocol(9999), None);
        assert_eq!(expected_protocol(1234), None);
        assert_eq!(expected_protocol(0), None);
    }
}
