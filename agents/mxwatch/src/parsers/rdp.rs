//! RDP (Remote Desktop Protocol) parser — feature 25.8.
//!
//! Extracts connection negotiation metadata from RDP sessions on port 3389 to
//! provide visibility into remote-access activity and detect weakened security
//! configurations such as missing Network Level Authentication (NLA).
//!
//! # Capabilities
//! - Parses the 4-byte TPKT header (RFC 1006) to validate packet structure.
//! - Decodes the X.224 Connection Request (CR) and Connection Confirm (CC)
//!   PDUs (ISO 8073 / ITU-T X.224 §13.3, §13.4).
//! - Extracts the RDP Negotiation Request (`RDP_NEG_REQ`) from within the
//!   X.224 CR user data field (MS-RDPBCGR §2.2.1.1.1).
//! - Parses the requested security protocol bitmask:
//!   - `PROTOCOL_RDP` (0x00): legacy encryption, no TLS or NLA.
//!   - `PROTOCOL_SSL` (0x01): TLS required.
//!   - `PROTOCOL_HYBRID` (0x02): NLA (CredSSP) required.
//!   - `PROTOCOL_RDSTLS` (0x04): RDSTLS.
//!   - `PROTOCOL_HYBRID_EX` (0x08): NLA with Early User Authorization.
//! - Detects suspicious configurations: missing NLA, legacy RDP encryption.
//!
//! # Limitations
//! - Only Connection Request (X.224 type 0xE0) and Connection Confirm
//!   (type 0xD0) PDUs are parsed; Data Transfer (0xF0) and other PDUs
//!   are beyond scope.
//! - The parser reads only the first TPKT packet; multi-packet fragmentation
//!   is not handled.
//! - TLS/NLA encryption begins after the connection confirm; no post-handshake
//!   RDP PDUs are parseable.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// RDP / TPKT / X.224 protocol constants
// ---------------------------------------------------------------------------

/// TPKT version field value (always 3 per RFC 1006 §2.1).
pub const TPKT_VERSION: u8 = 3;

/// Size of the TPKT header in bytes (version + reserved + length[2]).
pub const TPKT_HEADER_SIZE: usize = 4;

/// X.224 Connection Request PDU type (CR — ISO 8073 §13.3).
pub const X224_CR: u8 = 0xE0;

/// X.224 Connection Confirm PDU type (CC — ISO 8073 §13.4).
pub const X224_CC: u8 = 0xD0;

/// X.224 Data Transfer PDU type (DT — ISO 8073 §13.7).
pub const X224_DT: u8 = 0xF0;

/// X.224 header size within the TPKT payload (LI + PDU-type + DST[2] + SRC[2] + CLASS[1]).
pub const X224_HEADER_SIZE: usize = 7;

/// RDP Negotiation Request type byte (`RDP_NEG_REQ`, MS-RDPBCGR §2.2.1.1.1).
pub const RDP_NEG_REQ: u8 = 0x01;

/// RDP Negotiation Response type byte (`RDP_NEG_RSP`, MS-RDPBCGR §2.2.1.2.1).
pub const RDP_NEG_RSP: u8 = 0x02;

/// RDP Negotiation Failure type byte (`RDP_NEG_FAILURE`, MS-RDPBCGR §2.2.1.2.2).
pub const RDP_NEG_FAILURE: u8 = 0x03;

/// Size of the RDP Negotiation Request/Response structure in bytes.
pub const RDP_NEG_SIZE: usize = 8;

// RDP security protocol bitmask values (MS-RDPBCGR §2.2.1.1.1 — requestedProtocols).
/// Legacy RDP encryption (RC4); no TLS, no NLA.
pub const PROTOCOL_RDP: u32 = 0x0000_0000;
/// TLS 1.0/1.1/1.2 required for the transport.
pub const PROTOCOL_SSL: u32 = 0x0000_0001;
/// Network Level Authentication (CredSSP/NLA) required.
pub const PROTOCOL_HYBRID: u32 = 0x0000_0002;
/// RDSTLS security layer.
pub const PROTOCOL_RDSTLS: u32 = 0x0000_0004;
/// NLA with Early User Authorization Result PDU.
pub const PROTOCOL_HYBRID_EX: u32 = 0x0000_0008;

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// X.224 PDU type decoded from the TPKT payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum X224PduType {
    /// Connection Request (client → server).
    ConnectionRequest,
    /// Connection Confirm (server → client).
    ConnectionConfirm,
    /// Data Transfer (normal session data).
    Data,
    /// Other / unknown X.224 PDU type.
    Other(u8),
}

/// Parsed metadata from an RDP connection initiation packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RdpInfo {
    /// TPKT version byte (should always be 3).
    pub tpkt_version: u8,

    /// Total packet length as declared in the TPKT header (big-endian u16,
    /// includes the 4-byte TPKT header itself).
    pub tpkt_length: u16,

    /// X.224 PDU type extracted from the first byte after the TPKT header.
    pub pdu_type: X224PduType,

    /// RDP negotiation type byte, if an `RDP_NEG_REQ` or `RDP_NEG_RSP`
    /// structure was found in the X.224 user data field.
    pub neg_type: Option<u8>,

    /// Requested security protocol bitmask from `RDP_NEG_REQ` (little-endian
    /// u32).  `None` when no negotiation structure was present.
    pub requested_protocols: Option<u32>,

    /// True when NLA (CredSSP) is included in `requested_protocols`.
    ///
    /// Set when `PROTOCOL_HYBRID` (0x02) or `PROTOCOL_HYBRID_EX` (0x08) is
    /// present in the bitmask.
    pub nla_requested: bool,

    /// True when TLS is included in `requested_protocols`.
    pub tls_requested: bool,
}

// ---------------------------------------------------------------------------
// Public parsing API
// ---------------------------------------------------------------------------

/// Attempt to parse RDP connection metadata from a raw TCP payload.
///
/// The function validates the TPKT header, decodes the X.224 PDU type, and
/// attempts to read the optional `RDP_NEG_REQ` / `RDP_NEG_RSP` structure from
/// the X.224 user data field.
///
/// Returns `None` when the payload is too short, the TPKT version byte is not
/// 3, or no X.224 connection PDU is present.
pub fn parse_rdp(data: &[u8]) -> Option<RdpInfo> {
    // TPKT header minimum size check.
    if data.len() < TPKT_HEADER_SIZE {
        return None;
    }

    // Validate TPKT version byte (must be 3 per RFC 1006).
    let tpkt_version = data[0];
    if tpkt_version != TPKT_VERSION {
        return None;
    }

    // data[1] is reserved (always 0 in practice; we read but do not validate).
    let tpkt_length = u16::from_be_bytes([data[2], data[3]]);

    // The TPKT payload begins at offset 4.
    let tpkt_payload = &data[TPKT_HEADER_SIZE..];

    // X.224 header: LI(1) + PDU-type/credit(1) + DST-REF(2) + SRC-REF(2) + CLASS(1)
    // The PDU-type is encoded in the high nibble of byte[1] for CR/CC, but
    // for practical RDP parsing we read the full byte and match known values.
    if tpkt_payload.len() < 2 {
        return None;
    }

    // tpkt_payload[0] = X.224 LI (length indicator, excludes the LI byte itself)
    // tpkt_payload[1] = PDU type / credit byte
    let x224_pdu_byte = tpkt_payload[1];
    let pdu_type = match x224_pdu_byte {
        X224_CR => X224PduType::ConnectionRequest,
        X224_CC => X224PduType::ConnectionConfirm,
        X224_DT => X224PduType::Data,
        other => X224PduType::Other(other),
    };

    // X.224 user data starts after the 7-byte X.224 header.
    // For Data Transfer PDUs the structure differs; we only read NEG_REQ/RSP
    // from CR and CC PDUs.
    let (neg_type, requested_protocols, nla_requested, tls_requested) = if matches!(
        pdu_type,
        X224PduType::ConnectionRequest | X224PduType::ConnectionConfirm
    ) && tpkt_payload.len() >= X224_HEADER_SIZE + RDP_NEG_SIZE
    {
        let user_data = &tpkt_payload[X224_HEADER_SIZE..];
        parse_rdp_neg(user_data)
    } else {
        (None, None, false, false)
    };

    Some(RdpInfo {
        tpkt_version,
        tpkt_length,
        pdu_type,
        neg_type,
        requested_protocols,
        nla_requested,
        tls_requested,
    })
}

/// Return `true` if `port` is the standard RDP service port.
pub fn is_rdp_port(port: u16) -> bool {
    port == 3389
}

// ---------------------------------------------------------------------------
// Suspicion detection
// ---------------------------------------------------------------------------

/// Return `true` if the RDP connection metadata exhibits suspicious or
/// weakened security configurations.
///
/// Detection categories:
///
/// - **Legacy RDP encryption** (`PROTOCOL_RDP` only, no TLS/NLA): The
///   legacy RC4-based RDP encryption is breakable and does not authenticate
///   the server.  This configuration is associated with MITM attacks and
///   pass-the-hash credential relay.
///
/// - **TLS without NLA**: TLS protects the transport but does not pre-
///   authenticate the user before the RDP session is fully established,
///   making the host susceptible to credential brute-force via BlueKeep
///   and related vulnerabilities.
///
/// - **NLA requested**: Sessions requesting NLA (PROTOCOL_HYBRID or
///   PROTOCOL_HYBRID_EX) are considered normal; this function returns
///   `false` for those connections.
pub fn is_suspicious_rdp(info: &RdpInfo) -> bool {
    // Only evaluate Connection Request PDUs (from client).
    if info.pdu_type != X224PduType::ConnectionRequest {
        return false;
    }

    if let Some(protocols) = info.requested_protocols {
        // Legacy RDP-only encryption — no TLS, no NLA.
        if protocols == PROTOCOL_RDP {
            return true;
        }

        // TLS requested but NLA explicitly not included.
        let nla_mask = PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX;
        let tls_only = (protocols & PROTOCOL_SSL) != 0 && (protocols & nla_mask) == 0;
        if tls_only {
            return true;
        }
    }

    false
}

/// Return a human-readable description of the RDP protocol bitmask.
///
/// Example: `PROTOCOL_SSL | PROTOCOL_HYBRID`.
pub fn rdp_protocol_names(protocols: u32) -> String {
    let mut parts: Vec<&str> = Vec::new();
    if protocols == PROTOCOL_RDP {
        return "PROTOCOL_RDP (legacy)".to_string();
    }
    if (protocols & PROTOCOL_SSL) != 0 {
        parts.push("PROTOCOL_SSL");
    }
    if (protocols & PROTOCOL_HYBRID) != 0 {
        parts.push("PROTOCOL_HYBRID");
    }
    if (protocols & PROTOCOL_RDSTLS) != 0 {
        parts.push("PROTOCOL_RDSTLS");
    }
    if (protocols & PROTOCOL_HYBRID_EX) != 0 {
        parts.push("PROTOCOL_HYBRID_EX");
    }
    if parts.is_empty() {
        return format!("UNKNOWN(0x{protocols:08X})");
    }
    parts.join(" | ")
}

// ---------------------------------------------------------------------------
// Internal negotiation structure parser
// ---------------------------------------------------------------------------

/// Parse an `RDP_NEG_REQ` or `RDP_NEG_RSP` structure from X.224 user data.
///
/// Structure (MS-RDPBCGR §2.2.1.1.1 / §2.2.1.2.1, all little-endian):
/// ```text
/// byte    type            (0x01 = REQ, 0x02 = RSP, 0x03 = FAILURE)
/// byte    flags
/// uint16  length          (always 8)
/// uint32  requestedProtocols / selectedProtocol / failureCode
/// ```
///
/// Returns `(neg_type, protocols, nla_requested, tls_requested)`.
fn parse_rdp_neg(data: &[u8]) -> (Option<u8>, Option<u32>, bool, bool) {
    if data.len() < RDP_NEG_SIZE {
        return (None, None, false, false);
    }

    let neg_type = data[0];
    // Only parse protocol fields for REQ and RSP; ignore FAILURE.
    if !matches!(neg_type, RDP_NEG_REQ | RDP_NEG_RSP) {
        return (Some(neg_type), None, false, false);
    }

    // data[1] = flags, data[2..4] = length (should be 8).
    let protocols = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

    let nla_requested = (protocols & PROTOCOL_HYBRID) != 0
        || (protocols & PROTOCOL_HYBRID_EX) != 0;
    let tls_requested = (protocols & PROTOCOL_SSL) != 0;

    (Some(neg_type), Some(protocols), nla_requested, tls_requested)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Packet construction helpers
    // -----------------------------------------------------------------------

    /// Build a complete TPKT + X.224 CR + RDP_NEG_REQ packet.
    ///
    /// The X.224 CR carries the standard 7-byte header and an 8-byte
    /// `RDP_NEG_REQ` structure.  Total wire size = 4 + 7 + 8 = 19 bytes.
    fn build_rdp_cr(protocols: u32) -> Vec<u8> {
        let mut pkt = Vec::new();

        // TPKT header (4 bytes)
        let total_len: u16 = (TPKT_HEADER_SIZE + X224_HEADER_SIZE + RDP_NEG_SIZE) as u16;
        pkt.push(TPKT_VERSION);        // version = 3
        pkt.push(0x00);                // reserved
        pkt.extend_from_slice(&total_len.to_be_bytes()); // length (big-endian)

        // X.224 Connection Request header (7 bytes)
        // LI = 6 + 8 = 14 (header body length; LI excludes itself)
        // We set LI to cover CR header (6 bytes after LI) + user data (8 bytes).
        pkt.push(14u8); // LI
        pkt.push(X224_CR); // PDU type
        pkt.push(0x00); // DST-REF high
        pkt.push(0x00); // DST-REF low
        pkt.push(0x00); // SRC-REF high
        pkt.push(0x01); // SRC-REF low
        pkt.push(0x00); // class option

        // RDP_NEG_REQ (8 bytes)
        pkt.push(RDP_NEG_REQ);  // type
        pkt.push(0x00);         // flags
        pkt.push(0x08);         // length low
        pkt.push(0x00);         // length high
        pkt.extend_from_slice(&protocols.to_le_bytes()); // requestedProtocols

        pkt
    }

    /// Build a TPKT + X.224 CC + RDP_NEG_RSP packet.
    fn build_rdp_cc(selected_protocol: u32) -> Vec<u8> {
        let mut pkt = Vec::new();
        let total_len: u16 = (TPKT_HEADER_SIZE + X224_HEADER_SIZE + RDP_NEG_SIZE) as u16;
        pkt.push(TPKT_VERSION);
        pkt.push(0x00);
        pkt.extend_from_slice(&total_len.to_be_bytes());

        pkt.push(14u8);
        pkt.push(X224_CC); // Connection Confirm
        pkt.push(0x00);
        pkt.push(0x00);
        pkt.push(0x00);
        pkt.push(0x01);
        pkt.push(0x00);

        pkt.push(RDP_NEG_RSP); // type
        pkt.push(0x00);
        pkt.push(0x08);
        pkt.push(0x00);
        pkt.extend_from_slice(&selected_protocol.to_le_bytes());

        pkt
    }

    /// Build a TPKT + X.224 CR without any RDP_NEG_REQ (legacy clients).
    fn build_rdp_cr_no_neg() -> Vec<u8> {
        let mut pkt = Vec::new();
        let total_len: u16 = (TPKT_HEADER_SIZE + X224_HEADER_SIZE) as u16;
        pkt.push(TPKT_VERSION);
        pkt.push(0x00);
        pkt.extend_from_slice(&total_len.to_be_bytes());

        pkt.push(6u8); // LI = header body only
        pkt.push(X224_CR);
        pkt.push(0x00);
        pkt.push(0x00);
        pkt.push(0x00);
        pkt.push(0x01);
        pkt.push(0x00);

        pkt
    }

    // -----------------------------------------------------------------------
    // parse_rdp — basic validation
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_rdp_returns_none_on_empty() {
        assert!(parse_rdp(&[]).is_none());
    }

    #[test]
    fn test_parse_rdp_returns_none_on_short_data() {
        assert!(parse_rdp(&[0x03, 0x00]).is_none());
    }

    #[test]
    fn test_parse_rdp_returns_none_wrong_tpkt_version() {
        // Version byte = 2 → not valid TPKT.
        let data = vec![0x02, 0x00, 0x00, 0x13, 0x0E, X224_CR, 0, 0, 0, 1, 0];
        assert!(parse_rdp(&data).is_none());
    }

    #[test]
    fn test_parse_rdp_returns_none_on_garbage() {
        assert!(parse_rdp(b"GET / HTTP/1.1\r\n").is_none());
    }

    // -----------------------------------------------------------------------
    // parse_rdp — TPKT + X.224 fields
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_rdp_tpkt_version() {
        let pkt = build_rdp_cr(PROTOCOL_SSL | PROTOCOL_HYBRID);
        let info = parse_rdp(&pkt).expect("parse");
        assert_eq!(info.tpkt_version, 3);
    }

    #[test]
    fn test_parse_rdp_tpkt_length() {
        let pkt = build_rdp_cr(PROTOCOL_SSL | PROTOCOL_HYBRID);
        let info = parse_rdp(&pkt).expect("parse");
        assert_eq!(info.tpkt_length, 19); // 4 + 7 + 8
    }

    #[test]
    fn test_parse_rdp_pdu_type_connection_request() {
        let pkt = build_rdp_cr(PROTOCOL_SSL | PROTOCOL_HYBRID);
        let info = parse_rdp(&pkt).expect("parse");
        assert_eq!(info.pdu_type, X224PduType::ConnectionRequest);
    }

    #[test]
    fn test_parse_rdp_pdu_type_connection_confirm() {
        let pkt = build_rdp_cc(PROTOCOL_SSL | PROTOCOL_HYBRID);
        let info = parse_rdp(&pkt).expect("parse");
        assert_eq!(info.pdu_type, X224PduType::ConnectionConfirm);
    }

    // -----------------------------------------------------------------------
    // parse_rdp — RDP_NEG_REQ fields
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_rdp_nla_and_tls_requested() {
        // PROTOCOL_SSL (0x01) | PROTOCOL_HYBRID (0x02) = 0x03
        let pkt = build_rdp_cr(PROTOCOL_SSL | PROTOCOL_HYBRID);
        let info = parse_rdp(&pkt).expect("parse");
        assert_eq!(info.requested_protocols, Some(PROTOCOL_SSL | PROTOCOL_HYBRID));
        assert!(info.nla_requested);
        assert!(info.tls_requested);
    }

    #[test]
    fn test_parse_rdp_tls_only_no_nla() {
        let pkt = build_rdp_cr(PROTOCOL_SSL);
        let info = parse_rdp(&pkt).expect("parse");
        assert_eq!(info.requested_protocols, Some(PROTOCOL_SSL));
        assert!(!info.nla_requested);
        assert!(info.tls_requested);
    }

    #[test]
    fn test_parse_rdp_legacy_no_tls_no_nla() {
        let pkt = build_rdp_cr(PROTOCOL_RDP);
        let info = parse_rdp(&pkt).expect("parse");
        assert_eq!(info.requested_protocols, Some(PROTOCOL_RDP));
        assert!(!info.nla_requested);
        assert!(!info.tls_requested);
    }

    #[test]
    fn test_parse_rdp_hybrid_ex() {
        let pkt = build_rdp_cr(PROTOCOL_SSL | PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX);
        let info = parse_rdp(&pkt).expect("parse");
        assert!(info.nla_requested);
        assert!(info.tls_requested);
    }

    #[test]
    fn test_parse_rdp_neg_type_is_req() {
        let pkt = build_rdp_cr(PROTOCOL_SSL | PROTOCOL_HYBRID);
        let info = parse_rdp(&pkt).expect("parse");
        assert_eq!(info.neg_type, Some(RDP_NEG_REQ));
    }

    #[test]
    fn test_parse_rdp_cc_neg_type_is_rsp() {
        let pkt = build_rdp_cc(PROTOCOL_SSL | PROTOCOL_HYBRID);
        let info = parse_rdp(&pkt).expect("parse");
        assert_eq!(info.neg_type, Some(RDP_NEG_RSP));
    }

    #[test]
    fn test_parse_rdp_cr_without_neg_structure() {
        // Older RDP clients send CR without an RDP_NEG_REQ.
        let pkt = build_rdp_cr_no_neg();
        let info = parse_rdp(&pkt).expect("parse");
        assert_eq!(info.pdu_type, X224PduType::ConnectionRequest);
        assert!(info.requested_protocols.is_none());
        assert!(info.neg_type.is_none());
        assert!(!info.nla_requested);
        assert!(!info.tls_requested);
    }

    // -----------------------------------------------------------------------
    // is_rdp_port
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_rdp_port_standard() {
        assert!(is_rdp_port(3389));
    }

    #[test]
    fn test_is_rdp_port_non_rdp() {
        assert!(!is_rdp_port(3388));
        assert!(!is_rdp_port(80));
        assert!(!is_rdp_port(443));
        assert!(!is_rdp_port(22));
        assert!(!is_rdp_port(0));
        assert!(!is_rdp_port(65535));
    }

    // -----------------------------------------------------------------------
    // is_suspicious_rdp
    // -----------------------------------------------------------------------

    #[test]
    fn test_suspicious_rdp_legacy_protocol_only() {
        let info = RdpInfo {
            tpkt_version: 3,
            tpkt_length: 19,
            pdu_type: X224PduType::ConnectionRequest,
            neg_type: Some(RDP_NEG_REQ),
            requested_protocols: Some(PROTOCOL_RDP), // legacy RC4
            nla_requested: false,
            tls_requested: false,
        };
        assert!(is_suspicious_rdp(&info));
    }

    #[test]
    fn test_suspicious_rdp_tls_without_nla() {
        let info = RdpInfo {
            tpkt_version: 3,
            tpkt_length: 19,
            pdu_type: X224PduType::ConnectionRequest,
            neg_type: Some(RDP_NEG_REQ),
            requested_protocols: Some(PROTOCOL_SSL), // TLS but no NLA
            nla_requested: false,
            tls_requested: true,
        };
        assert!(is_suspicious_rdp(&info));
    }

    #[test]
    fn test_not_suspicious_rdp_nla_requested() {
        let info = RdpInfo {
            tpkt_version: 3,
            tpkt_length: 19,
            pdu_type: X224PduType::ConnectionRequest,
            neg_type: Some(RDP_NEG_REQ),
            requested_protocols: Some(PROTOCOL_SSL | PROTOCOL_HYBRID),
            nla_requested: true,
            tls_requested: true,
        };
        assert!(!is_suspicious_rdp(&info));
    }

    #[test]
    fn test_not_suspicious_rdp_hybrid_ex() {
        let info = RdpInfo {
            tpkt_version: 3,
            tpkt_length: 19,
            pdu_type: X224PduType::ConnectionRequest,
            neg_type: Some(RDP_NEG_REQ),
            requested_protocols: Some(PROTOCOL_SSL | PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX),
            nla_requested: true,
            tls_requested: true,
        };
        assert!(!is_suspicious_rdp(&info));
    }

    #[test]
    fn test_not_suspicious_rdp_connection_confirm() {
        // is_suspicious_rdp only evaluates CR PDUs; CC is not flagged.
        let info = RdpInfo {
            tpkt_version: 3,
            tpkt_length: 19,
            pdu_type: X224PduType::ConnectionConfirm,
            neg_type: Some(RDP_NEG_RSP),
            requested_protocols: Some(PROTOCOL_RDP), // legacy, but CC not evaluated
            nla_requested: false,
            tls_requested: false,
        };
        assert!(!is_suspicious_rdp(&info));
    }

    #[test]
    fn test_not_suspicious_rdp_no_neg_structure() {
        // CR with no RDP_NEG_REQ: `requested_protocols` is None → not flagged.
        let info = RdpInfo {
            tpkt_version: 3,
            tpkt_length: 11,
            pdu_type: X224PduType::ConnectionRequest,
            neg_type: None,
            requested_protocols: None,
            nla_requested: false,
            tls_requested: false,
        };
        assert!(!is_suspicious_rdp(&info));
    }

    // -----------------------------------------------------------------------
    // rdp_protocol_names
    // -----------------------------------------------------------------------

    #[test]
    fn test_rdp_protocol_names_legacy() {
        assert!(rdp_protocol_names(PROTOCOL_RDP).contains("legacy"));
    }

    #[test]
    fn test_rdp_protocol_names_ssl_hybrid() {
        let s = rdp_protocol_names(PROTOCOL_SSL | PROTOCOL_HYBRID);
        assert!(s.contains("PROTOCOL_SSL"));
        assert!(s.contains("PROTOCOL_HYBRID"));
    }

    #[test]
    fn test_rdp_protocol_names_all_flags() {
        let proto = PROTOCOL_SSL | PROTOCOL_HYBRID | PROTOCOL_RDSTLS | PROTOCOL_HYBRID_EX;
        let s = rdp_protocol_names(proto);
        assert!(s.contains("PROTOCOL_SSL"));
        assert!(s.contains("PROTOCOL_HYBRID"));
        assert!(s.contains("PROTOCOL_RDSTLS"));
        assert!(s.contains("PROTOCOL_HYBRID_EX"));
    }

    // -----------------------------------------------------------------------
    // End-to-end: parse then check suspicion
    // -----------------------------------------------------------------------

    #[test]
    fn test_e2e_rdp_legacy_cr_suspicious() {
        let pkt = build_rdp_cr(PROTOCOL_RDP);
        let info = parse_rdp(&pkt).expect("parse");
        assert!(is_suspicious_rdp(&info));
    }

    #[test]
    fn test_e2e_rdp_tls_only_suspicious() {
        let pkt = build_rdp_cr(PROTOCOL_SSL);
        let info = parse_rdp(&pkt).expect("parse");
        assert!(is_suspicious_rdp(&info));
    }

    #[test]
    fn test_e2e_rdp_nla_cr_not_suspicious() {
        let pkt = build_rdp_cr(PROTOCOL_SSL | PROTOCOL_HYBRID);
        let info = parse_rdp(&pkt).expect("parse");
        assert!(!is_suspicious_rdp(&info));
    }

    #[test]
    fn test_e2e_rdp_cc_not_suspicious() {
        let pkt = build_rdp_cc(PROTOCOL_RDP); // legacy selected
        let info = parse_rdp(&pkt).expect("parse");
        // Connection Confirm PDUs are not evaluated.
        assert!(!is_suspicious_rdp(&info));
    }
}
