//! UDP header parser.

use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use serde::{Deserialize, Serialize};

/// Extracted UDP metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpInfo {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub payload_len: usize,
}

/// Parse a UDP header from a raw byte slice.
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
}
