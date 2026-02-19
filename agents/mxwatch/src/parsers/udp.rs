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
