//! Protocol parsers for MxWatch.
//!
//! Each parser takes raw packet bytes (or a higher-layer payload) and
//! produces structured metadata that downstream detectors consume.

pub mod tcp;
pub mod udp;
pub mod dns;
pub mod http;
pub mod tls;
pub mod smb;
pub mod ssh;
pub mod rdp;

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

// ---------------------------------------------------------------------------
// Shared types used across parsers
// ---------------------------------------------------------------------------

/// A parsed network flow record carrying protocol-specific metadata.
/// This type is part of the architectural scaffolding and will be used
/// when flow-level aggregation is implemented.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedFlow {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: FlowProtocol,
    pub payload_len: usize,
    pub detail: FlowDetail,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FlowProtocol {
    Tcp,
    Udp,
}

/// Protocol-specific parsed details.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FlowDetail {
    Tcp(tcp::TcpInfo),
    Udp(udp::UdpInfo),
    Dns(dns::DnsInfo),
    Http(http::HttpInfo),
    Tls(tls::TlsInfo),
    Smb(smb::SmbInfo),
    Ssh(ssh::SshInfo),
    Rdp(rdp::RdpInfo),
    /// No higher-layer parsing was performed.
    None,
}
