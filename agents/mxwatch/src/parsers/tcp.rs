//! TCP header parser.

use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use serde::{Deserialize, Serialize};

/// Extracted TCP metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpInfo {
    pub src_port: u16,
    pub dst_port: u16,
    pub flags: TcpFlags,
    pub seq: u32,
    pub ack: u32,
    pub window: u16,
    pub payload_len: usize,
}

/// Decoded TCP flag bits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
    pub urg: bool,
}

/// Parse a TCP header from a raw byte slice.
pub fn parse_tcp(data: &[u8]) -> Option<TcpInfo> {
    let pkt = TcpPacket::new(data)?;
    let flags_raw = pkt.get_flags();

    Some(TcpInfo {
        src_port: pkt.get_source(),
        dst_port: pkt.get_destination(),
        flags: TcpFlags {
            syn: flags_raw & 0x02 != 0,
            ack: flags_raw & 0x10 != 0,
            fin: flags_raw & 0x01 != 0,
            rst: flags_raw & 0x04 != 0,
            psh: flags_raw & 0x08 != 0,
            urg: flags_raw & 0x20 != 0,
        },
        seq: pkt.get_sequence(),
        ack: pkt.get_acknowledgement(),
        window: pkt.get_window(),
        payload_len: pkt.payload().len(),
    })
}

/// Check if this looks like a SYN scan (SYN set, ACK not set).
pub fn is_syn_only(info: &TcpInfo) -> bool {
    info.flags.syn && !info.flags.ack
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid 20-byte TCP header.
    ///
    /// Layout (RFC 793):
    ///   src_port(2) dst_port(2) seq(4) ack(4)
    ///   data_offset+flags(2) window(2) checksum(2) urgent(2)
    fn make_tcp_header(src_port: u16, dst_port: u16, flags: u8) -> Vec<u8> {
        let mut h = vec![0u8; 20];
        // src_port
        h[0] = (src_port >> 8) as u8;
        h[1] = (src_port & 0xFF) as u8;
        // dst_port
        h[2] = (dst_port >> 8) as u8;
        h[3] = (dst_port & 0xFF) as u8;
        // seq = 0, ack = 0 (bytes 4-11 already zeroed)
        // data_offset = 5 (header = 20 bytes, offset field = 5*4=20)
        h[12] = 0x50; // data_offset=5, reserved=0, NS=0
        h[13] = flags; // flag bits
        // window = 65535
        h[14] = 0xFF;
        h[15] = 0xFF;
        // checksum = 0, urgent = 0
        h
    }

    // -----------------------------------------------------------------------
    // parse_tcp
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_tcp_too_short_returns_none() {
        assert!(parse_tcp(&[]).is_none());
        assert!(parse_tcp(&[0u8; 10]).is_none());
    }

    #[test]
    fn test_parse_tcp_basic_ports() {
        let hdr = make_tcp_header(80, 12345, 0x00);
        let info = parse_tcp(&hdr).expect("parse");
        assert_eq!(info.src_port, 80);
        assert_eq!(info.dst_port, 12345);
        assert_eq!(info.window, 0xFFFF);
        assert_eq!(info.payload_len, 0);
    }

    #[test]
    fn test_parse_tcp_syn_flag() {
        let hdr = make_tcp_header(1024, 443, 0x02); // SYN
        let info = parse_tcp(&hdr).expect("parse");
        assert!(info.flags.syn);
        assert!(!info.flags.ack);
        assert!(!info.flags.fin);
        assert!(!info.flags.rst);
    }

    #[test]
    fn test_parse_tcp_syn_ack_flags() {
        let hdr = make_tcp_header(443, 1024, 0x12); // SYN + ACK
        let info = parse_tcp(&hdr).expect("parse");
        assert!(info.flags.syn);
        assert!(info.flags.ack);
        assert!(!info.flags.fin);
    }

    #[test]
    fn test_parse_tcp_fin_flag() {
        let hdr = make_tcp_header(1024, 80, 0x01); // FIN
        let info = parse_tcp(&hdr).expect("parse");
        assert!(info.flags.fin);
        assert!(!info.flags.syn);
    }

    #[test]
    fn test_parse_tcp_rst_flag() {
        let hdr = make_tcp_header(1024, 80, 0x04); // RST
        let info = parse_tcp(&hdr).expect("parse");
        assert!(info.flags.rst);
    }

    // -----------------------------------------------------------------------
    // is_syn_only
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_syn_only_true_for_pure_syn() {
        let hdr = make_tcp_header(1024, 80, 0x02);
        let info = parse_tcp(&hdr).expect("parse");
        assert!(is_syn_only(&info));
    }

    #[test]
    fn test_is_syn_only_false_for_syn_ack() {
        let hdr = make_tcp_header(80, 1024, 0x12); // SYN + ACK
        let info = parse_tcp(&hdr).expect("parse");
        assert!(!is_syn_only(&info));
    }

    #[test]
    fn test_is_syn_only_false_for_plain_ack() {
        let hdr = make_tcp_header(80, 1024, 0x10); // ACK only
        let info = parse_tcp(&hdr).expect("parse");
        assert!(!is_syn_only(&info));
    }
}
