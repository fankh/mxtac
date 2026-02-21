//! UDP header parser with service classification helpers.
//!
//! Feature 25.4 — Protocol parser: TCP/UDP
//! Parses the fixed 8-byte UDP header, provides a zero-copy payload extractor,
//! and maps well-known ports to service names.

use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Struct
// ---------------------------------------------------------------------------

/// Extracted UDP metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpInfo {
    pub src_port: u16,
    pub dst_port: u16,
    /// Total length declared in the UDP header (header + payload, in bytes).
    pub length: u16,
    pub payload_len: usize,
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse a UDP header from a raw byte slice.
///
/// Returns `None` if `data` is shorter than the 8-byte UDP header.
pub fn parse_udp(data: &[u8]) -> Option<UdpInfo> {
    let pkt = UdpPacket::new(data)?;
    Some(UdpInfo {
        src_port: pkt.get_source(),
        dst_port: pkt.get_destination(),
        length: pkt.get_length(),
        payload_len: pkt.payload().len(),
    })
}

// ---------------------------------------------------------------------------
// Payload helper
// ---------------------------------------------------------------------------

/// Extract the UDP payload from the raw datagram bytes, skipping the 8-byte
/// fixed header.
///
/// Returns an empty slice when `data` is 8 bytes or shorter (header-only or
/// truncated).
pub fn extract_payload(data: &[u8]) -> &[u8] {
    const UDP_HEADER_LEN: usize = 8;
    if data.len() > UDP_HEADER_LEN {
        &data[UDP_HEADER_LEN..]
    } else {
        &[]
    }
}

// ---------------------------------------------------------------------------
// Port classification helpers
// ---------------------------------------------------------------------------

/// Return `true` when either endpoint uses a DNS port (53 for DNS, 5353 for mDNS).
pub fn is_dns_port(info: &UdpInfo) -> bool {
    info.src_port == 53
        || info.dst_port == 53
        || info.src_port == 5353
        || info.dst_port == 5353
}

/// Return `true` when either endpoint uses a DHCP port
/// (67 = server/bootstrap, 68 = client).
pub fn is_dhcp_port(info: &UdpInfo) -> bool {
    matches!(info.src_port, 67 | 68) || matches!(info.dst_port, 67 | 68)
}

// ---------------------------------------------------------------------------
// Service name mapping
// ---------------------------------------------------------------------------

/// Return a well-known service name for a UDP port number, or `None` for
/// unknown / ephemeral ports.
pub fn service_name_for_port(port: u16) -> Option<&'static str> {
    match port {
        53 => Some("DNS"),
        67 | 68 => Some("DHCP"),
        69 => Some("TFTP"),
        123 => Some("NTP"),
        161 | 162 => Some("SNMP"),
        500 => Some("IKE"),
        514 => Some("Syslog"),
        1194 => Some("OpenVPN"),
        4500 => Some("IPSec-NAT-T"),
        5353 => Some("mDNS"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid 8-byte UDP header (no payload).
    fn make_udp_header(src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut h = vec![0u8; 8];
        h[0] = (src_port >> 8) as u8;
        h[1] = (src_port & 0xFF) as u8;
        h[2] = (dst_port >> 8) as u8;
        h[3] = (dst_port & 0xFF) as u8;
        // length = 8 (header only)
        h[4] = 0x00;
        h[5] = 0x08;
        // checksum = 0
        h
    }

    // -----------------------------------------------------------------------
    // parse_udp
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_udp_too_short_returns_none() {
        assert!(parse_udp(&[]).is_none());
        assert!(parse_udp(&[0u8; 7]).is_none());
    }

    #[test]
    fn test_parse_udp_basic_ports() {
        let hdr = make_udp_header(53, 1024);
        let info = parse_udp(&hdr).expect("parse");
        assert_eq!(info.src_port, 53);
        assert_eq!(info.dst_port, 1024);
        assert_eq!(info.length, 8);
        assert_eq!(info.payload_len, 0);
    }

    #[test]
    fn test_parse_udp_with_payload() {
        let mut data = make_udp_header(5353, 5353);
        data.extend_from_slice(b"mDNS"); // 4 bytes of fake payload
        // Update length field to 12.
        data[4] = 0x00;
        data[5] = 0x0C;
        let info = parse_udp(&data).expect("parse");
        assert_eq!(info.src_port, 5353);
        assert_eq!(info.payload_len, 4);
    }

    #[test]
    fn test_parse_udp_dns_port_53() {
        let hdr = make_udp_header(1234, 53);
        let info = parse_udp(&hdr).expect("parse");
        assert_eq!(info.dst_port, 53);
    }

    // -----------------------------------------------------------------------
    // extract_payload
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_payload_returns_data_after_header() {
        let mut data = make_udp_header(53, 1024);
        data.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let payload = extract_payload(&data);
        assert_eq!(payload, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_extract_payload_empty_for_header_only() {
        let hdr = make_udp_header(53, 1024);
        let payload = extract_payload(&hdr);
        assert!(payload.is_empty());
    }

    #[test]
    fn test_extract_payload_empty_for_short_data() {
        let payload = extract_payload(&[0u8; 4]);
        assert!(payload.is_empty());
    }

    // -----------------------------------------------------------------------
    // is_dns_port
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_dns_port_src_53() {
        let hdr = make_udp_header(53, 1024);
        let info = parse_udp(&hdr).expect("parse");
        assert!(is_dns_port(&info));
    }

    #[test]
    fn test_is_dns_port_dst_53() {
        let hdr = make_udp_header(1024, 53);
        let info = parse_udp(&hdr).expect("parse");
        assert!(is_dns_port(&info));
    }

    #[test]
    fn test_is_dns_port_mdns_5353() {
        let hdr = make_udp_header(5353, 5353);
        let info = parse_udp(&hdr).expect("parse");
        assert!(is_dns_port(&info));
    }

    #[test]
    fn test_is_dns_port_false_for_other() {
        let hdr = make_udp_header(1234, 5678);
        let info = parse_udp(&hdr).expect("parse");
        assert!(!is_dns_port(&info));
    }

    // -----------------------------------------------------------------------
    // is_dhcp_port
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_dhcp_port_server_to_client() {
        let hdr = make_udp_header(67, 68);
        let info = parse_udp(&hdr).expect("parse");
        assert!(is_dhcp_port(&info));
    }

    #[test]
    fn test_is_dhcp_port_client_to_server() {
        let hdr = make_udp_header(68, 67);
        let info = parse_udp(&hdr).expect("parse");
        assert!(is_dhcp_port(&info));
    }

    #[test]
    fn test_is_dhcp_port_false() {
        let hdr = make_udp_header(1234, 5678);
        let info = parse_udp(&hdr).expect("parse");
        assert!(!is_dhcp_port(&info));
    }

    // -----------------------------------------------------------------------
    // service_name_for_port
    // -----------------------------------------------------------------------

    #[test]
    fn test_service_name_for_port_known() {
        assert_eq!(service_name_for_port(53), Some("DNS"));
        assert_eq!(service_name_for_port(67), Some("DHCP"));
        assert_eq!(service_name_for_port(68), Some("DHCP"));
        assert_eq!(service_name_for_port(123), Some("NTP"));
        assert_eq!(service_name_for_port(161), Some("SNMP"));
        assert_eq!(service_name_for_port(162), Some("SNMP"));
        assert_eq!(service_name_for_port(5353), Some("mDNS"));
    }

    #[test]
    fn test_service_name_for_port_unknown() {
        assert_eq!(service_name_for_port(12345), None);
        assert_eq!(service_name_for_port(0), None);
        assert_eq!(service_name_for_port(65535), None);
    }
}
