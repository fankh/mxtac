//! Integration tests for IPv6 packet parsing and OCSF serialization.
//!
//! Verifies that the MxWatch packet processing pipeline correctly handles
//! IPv6 frames: EtherType 0x86DD detection, source/destination address
//! extraction, transport-layer routing, and OCSF event construction.

use std::net::{IpAddr, Ipv6Addr};
use std::str::FromStr;

use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::Packet;

use mxwatch::events::ocsf::{OcsfDevice, OcsfEndpoint, OcsfNetworkEvent};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Builds a raw Ethernet + IPv6 + UDP frame with the given source/destination
/// IPv6 addresses and UDP ports.  The UDP payload is zeroed.
fn build_ipv6_udp_frame(
    src_addr: Ipv6Addr,
    dst_addr: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
    udp_payload: &[u8],
) -> Vec<u8> {
    let udp_len: usize = 8 + udp_payload.len(); // 8-byte UDP header
    let ipv6_payload_len: usize = udp_len;
    let total: usize = 14 + 40 + udp_len; // eth + ipv6 + udp

    let mut raw = vec![0u8; total];

    // Ethernet header (14 bytes)
    {
        let mut eth = MutableEthernetPacket::new(&mut raw).unwrap();
        eth.set_ethertype(EtherTypes::Ipv6);
        // MAC addresses default to zeros — fine for unit tests
    }

    // IPv6 header (40 bytes, offset 14)
    {
        let mut ipv6 = MutableIpv6Packet::new(&mut raw[14..]).unwrap();
        ipv6.set_version(6);
        ipv6.set_traffic_class(0);
        ipv6.set_flow_label(0);
        ipv6.set_payload_length(ipv6_payload_len as u16);
        ipv6.set_next_header(IpNextHeaderProtocols::Udp);
        ipv6.set_hop_limit(64);
        ipv6.set_source(src_addr);
        ipv6.set_destination(dst_addr);
    }

    // UDP header (8 bytes, offset 14 + 40 = 54)
    {
        let mut udp = MutableUdpPacket::new(&mut raw[54..]).unwrap();
        udp.set_source(src_port);
        udp.set_destination(dst_port);
        udp.set_length(udp_len as u16);
        udp.set_checksum(0); // zero checksum (not validated in unit tests)
        // Copy payload after the 8-byte header
        let end = 54 + 8 + udp_payload.len();
        raw[62..end].copy_from_slice(udp_payload);
    }

    raw
}

fn test_device() -> OcsfDevice {
    OcsfDevice {
        hostname: "test-sensor".into(),
        ip: "::1".into(),
        os_name: "Linux".into(),
    }
}

// ---------------------------------------------------------------------------
// Ethernet / IPv6 parsing
// ---------------------------------------------------------------------------

#[test]
fn test_ethertype_is_ipv6() {
    let src = Ipv6Addr::from_str("2001:db8::1").unwrap();
    let dst = Ipv6Addr::from_str("2001:db8::2").unwrap();
    let raw = build_ipv6_udp_frame(src, dst, 12345, 53, &[]);

    let eth = EthernetPacket::new(&raw).unwrap();
    assert_eq!(eth.get_ethertype(), EtherTypes::Ipv6);
}

#[test]
fn test_ipv6_source_address_extracted() {
    let src = Ipv6Addr::from_str("2001:db8::cafe").unwrap();
    let dst = Ipv6Addr::from_str("2001:db8::1").unwrap();
    let raw = build_ipv6_udp_frame(src, dst, 54321, 80, &[]);

    let eth = EthernetPacket::new(&raw).unwrap();
    let ipv6 = Ipv6Packet::new(eth.payload()).unwrap();

    let src_ip = IpAddr::V6(ipv6.get_source());
    assert_eq!(src_ip.to_string(), "2001:db8::cafe");
}

#[test]
fn test_ipv6_destination_address_extracted() {
    let src = Ipv6Addr::from_str("fe80::1").unwrap();
    let dst = Ipv6Addr::from_str("ff02::2").unwrap();
    let raw = build_ipv6_udp_frame(src, dst, 1234, 443, &[]);

    let eth = EthernetPacket::new(&raw).unwrap();
    let ipv6 = Ipv6Packet::new(eth.payload()).unwrap();

    let dst_ip = IpAddr::V6(ipv6.get_destination());
    assert_eq!(dst_ip.to_string(), "ff02::2");
}

#[test]
fn test_ipv6_loopback_addresses() {
    let src = Ipv6Addr::LOCALHOST; // ::1
    let dst = Ipv6Addr::LOCALHOST;
    let raw = build_ipv6_udp_frame(src, dst, 9000, 53, &[]);

    let eth = EthernetPacket::new(&raw).unwrap();
    let ipv6 = Ipv6Packet::new(eth.payload()).unwrap();

    let src_ip = IpAddr::V6(ipv6.get_source());
    let dst_ip = IpAddr::V6(ipv6.get_destination());
    assert_eq!(src_ip.to_string(), "::1");
    assert_eq!(dst_ip.to_string(), "::1");
}

// ---------------------------------------------------------------------------
// Next-header protocol routing
// ---------------------------------------------------------------------------

#[test]
fn test_ipv6_next_header_is_udp() {
    let raw = build_ipv6_udp_frame(
        Ipv6Addr::from_str("2001:db8::1").unwrap(),
        Ipv6Addr::from_str("2001:db8::2").unwrap(),
        12345,
        53,
        &[],
    );

    let eth = EthernetPacket::new(&raw).unwrap();
    let ipv6 = Ipv6Packet::new(eth.payload()).unwrap();
    assert_eq!(ipv6.get_next_header(), IpNextHeaderProtocols::Udp);
}

#[test]
fn test_ipv6_transport_payload_length() {
    let payload_data = b"hello world";
    let raw = build_ipv6_udp_frame(
        Ipv6Addr::from_str("2001:db8::1").unwrap(),
        Ipv6Addr::from_str("2001:db8::2").unwrap(),
        12345,
        53,
        payload_data,
    );

    let eth = EthernetPacket::new(&raw).unwrap();
    let ipv6 = Ipv6Packet::new(eth.payload()).unwrap();

    // IPv6 payload = UDP header (8) + data (11) = 19 bytes
    let transport = ipv6.payload().to_vec();
    assert_eq!(transport.len(), 8 + payload_data.len());
}

#[test]
fn test_ipv6_payload_too_short_returns_none() {
    // An IPv6 packet requires exactly 40 bytes for its fixed header.
    // A buffer shorter than that must return None from Ipv6Packet::new().
    let short_buf = vec![0u8; 14 + 39]; // 14 eth + 39 (one byte short)
    let eth = EthernetPacket::new(&short_buf).unwrap();
    let result = Ipv6Packet::new(eth.payload());
    assert!(result.is_none(), "expected None for undersized IPv6 buffer");
}

// ---------------------------------------------------------------------------
// OCSF event construction with IPv6 addresses
// ---------------------------------------------------------------------------

#[test]
fn test_ocsf_endpoint_ipv6_address() {
    let ip = IpAddr::V6(Ipv6Addr::from_str("2001:db8::1").unwrap());
    let ep = OcsfEndpoint::new(ip, 443);
    assert_eq!(ep.ip, "2001:db8::1");
    assert_eq!(ep.port, 443);
}

#[test]
fn test_ocsf_traffic_event_ipv6_endpoints() {
    let src = IpAddr::V6(Ipv6Addr::from_str("2001:db8::cafe").unwrap());
    let dst = IpAddr::V6(Ipv6Addr::from_str("2001:db8::1").unwrap());

    let ev = OcsfNetworkEvent::traffic(test_device(), src, 54321, dst, 53, "DNS", 1);

    assert_eq!(ev.src_endpoint.ip, "2001:db8::cafe");
    assert_eq!(ev.src_endpoint.port, 54321);
    assert_eq!(ev.dst_endpoint.ip, "2001:db8::1");
    assert_eq!(ev.dst_endpoint.port, 53);
    assert_eq!(ev.class_uid, 4001);
}

#[test]
fn test_ocsf_traffic_event_ipv6_json_serialization() {
    let src = IpAddr::V6(Ipv6Addr::from_str("fe80::dead:beef").unwrap());
    let dst = IpAddr::V6(Ipv6Addr::from_str("ff02::fb").unwrap());

    let ev = OcsfNetworkEvent::traffic(test_device(), src, 5353, dst, 5353, "DNS", 1);
    let json = serde_json::to_string(&ev).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert_eq!(v["src_endpoint"]["ip"], "fe80::dead:beef");
    assert_eq!(v["dst_endpoint"]["ip"], "ff02::fb");
    assert_eq!(v["connection_info"]["protocol_name"], "DNS");
}

#[test]
fn test_ocsf_alert_event_ipv6() {
    use mxwatch::detectors::{Alert, AlertSeverity};

    let src = IpAddr::V6(Ipv6Addr::from_str("2001:db8::bad:1").unwrap());
    let dst = IpAddr::V6(Ipv6Addr::from_str("2001:db8::bad:2").unwrap());

    let alert = Alert {
        detector: "port_scan".into(),
        severity: AlertSeverity::High,
        description: "IPv6 port scan detected".into(),
        evidence: serde_json::json!({
            "src_ip": "2001:db8::bad:1",
            "distinct_ports": 10,
        }),
    };

    let ev = OcsfNetworkEvent::from_alert(test_device(), src, 0, dst, 22, "TCP", &alert);

    assert_eq!(ev.activity, "Detection");
    assert_eq!(ev.src_endpoint.ip, "2001:db8::bad:1");
    assert_eq!(ev.dst_endpoint.ip, "2001:db8::bad:2");
    let det = ev.detection.unwrap();
    assert_eq!(det.detector, "port_scan");
}

// ---------------------------------------------------------------------------
// UDP parser compatibility with IPv6 transport payload
// ---------------------------------------------------------------------------

#[test]
fn test_udp_parser_works_on_ipv6_transport_payload() {
    use mxwatch::parsers::udp;

    // Build an IPv6+UDP frame where the UDP header has known port values.
    let payload_data = b"DNS-query-bytes";
    let raw = build_ipv6_udp_frame(
        Ipv6Addr::from_str("2001:db8::1").unwrap(),
        Ipv6Addr::from_str("2001:db8::53").unwrap(),
        54321,
        53,
        payload_data,
    );

    let eth = EthernetPacket::new(&raw).unwrap();
    let ipv6 = Ipv6Packet::new(eth.payload()).unwrap();
    // Extract the IPv6 payload (= UDP segment) exactly as main.rs does.
    let transport = ipv6.payload().to_vec();

    let udp_info = udp::parse_udp(&transport).expect("UDP parse failed on IPv6 transport payload");
    assert_eq!(udp_info.src_port, 54321);
    assert_eq!(udp_info.dst_port, 53);
    assert!(udp::is_dns_port(&udp_info), "port 53 should be identified as DNS");
}

// ---------------------------------------------------------------------------
// Port scan detector with IPv6 source addresses
// ---------------------------------------------------------------------------

#[test]
fn test_port_scan_detector_ipv6_src() {
    use mxwatch::config::PortScanDetectorConfig;
    use mxwatch::detectors::port_scan::PortScanDetector;

    let mut det = PortScanDetector::new(&PortScanDetectorConfig {
        enabled: true,
        threshold_ports: 3,
        window_secs: 60,
    });

    let ipv6_src = "2001:db8::bad:1";
    assert!(det.record(ipv6_src, 80).is_none());
    assert!(det.record(ipv6_src, 443).is_none());
    let alert = det.record(ipv6_src, 8080);
    assert!(alert.is_some(), "port scan alert should fire for IPv6 source");
    let alert = alert.unwrap();
    assert!(alert.description.contains(ipv6_src));
    assert_eq!(alert.detector, "port_scan");
}
