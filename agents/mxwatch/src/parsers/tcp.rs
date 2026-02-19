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
