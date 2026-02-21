//! Feature 25.17 — Performance benchmark: 1–5 Mpps target.
//!
//! Measures the throughput of the MxWatch packet-processing pipeline at each
//! layer so that bottlenecks can be identified and the 1–5 Mpps design goal
//! can be verified.
//!
//! # Benchmark groups
//!
//! | Group        | What is measured                                  |
//! |--------------|---------------------------------------------------|
//! | `parsers`    | Individual protocol parsers (TCP, UDP, DNS, HTTP, TLS) |
//! | `detectors`  | Stateless detectors (proto anomaly) and setup cost |
//! | `pipeline`   | Full Ethernet → IPv4 → L4 → parser → detector path |
//!
//! # Interpreting results
//!
//! Criterion reports time per iteration.  To convert to Mpps:
//!
//! ```text
//! Mpps = 1 / (time_per_packet_in_microseconds)
//! ```
//!
//! Examples:
//! - 200 ns/pkt  → 5.0 Mpps
//! - 500 ns/pkt  → 2.0 Mpps
//! - 1 000 ns/pkt → 1.0 Mpps

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use mxwatch::config::{PortScanDetectorConfig, ProtoAnomalyDetectorConfig};
use mxwatch::detectors::port_scan::PortScanDetector;
use mxwatch::detectors::proto_anomaly::ProtoAnomalyDetector;
use mxwatch::parsers::{dns, http as http_parser, tcp, tls, udp};

use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;

// ---------------------------------------------------------------------------
// Test-packet fixtures
// ---------------------------------------------------------------------------
// All byte arrays encode valid, parseable packets.  Checksums are zeroed
// because neither pnet nor the parsers validate them.

/// Minimal 20-byte TCP SYN segment (no payload).
///
/// src_port=49152, dst_port=80, seq=1, SYN, window=65535
const RAW_TCP_SYN: &[u8] = &[
    0xc0, 0x00, // src_port: 49152
    0x00, 0x50, // dst_port: 80 (HTTP)
    0x00, 0x00, 0x00, 0x01, // seq: 1
    0x00, 0x00, 0x00, 0x00, // ack: 0
    0x50, 0x02, // data_offset=5 (20 B), flags=SYN
    0xff, 0xff, // window: 65535
    0x00, 0x00, // checksum
    0x00, 0x00, // urgent ptr
];

/// TCP segment carrying an HTTP GET request.
const RAW_TCP_HTTP: &[u8] = &[
    0xc0, 0x01, // src_port: 49153
    0x00, 0x50, // dst_port: 80
    0x00, 0x00, 0x00, 0x02, // seq: 2
    0x00, 0x00, 0x00, 0x01, // ack: 1
    0x50, 0x18, // data_offset=5, flags=PSH|ACK
    0xff, 0xff, // window
    0x00, 0x00, // checksum
    0x00, 0x00, // urgent ptr
    // HTTP GET payload
    b'G', b'E', b'T', b' ', b'/', b'i', b'n', b'd', b'e', b'x', b'.', b'h', b't', b'm', b'l',
    b' ', b'H', b'T', b'T', b'P', b'/', b'1', b'.', b'1', b'\r', b'\n', b'H', b'o', b's', b't',
    b':', b' ', b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', b'\r', b'\n',
    b'U', b's', b'e', b'r', b'-', b'A', b'g', b'e', b'n', b't', b':', b' ', b'M', b'o', b'z',
    b'i', b'l', b'l', b'a', b'/', b'5', b'.', b'0', b'\r', b'\n', b'\r', b'\n',
];

/// Standalone DNS query for "example.com" A record (wire format, no UDP header).
///
/// Layout: 12-byte header + 17-byte question section = 29 bytes.
const RAW_DNS_QUERY: &[u8] = &[
    0x12, 0x34, // Transaction ID
    0x01, 0x00, // Flags: standard query, RD=1
    0x00, 0x01, // QDCOUNT: 1
    0x00, 0x00, // ANCOUNT: 0
    0x00, 0x00, // NSCOUNT: 0
    0x00, 0x00, // ARCOUNT: 0
    // QNAME: example.com
    0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // "example" (7)
    0x03, b'c', b'o', b'm', // "com" (3)
    0x00,       // end of name
    0x00, 0x01, // QTYPE: A
    0x00, 0x01, // QCLASS: IN
];

/// Standalone HTTP GET request bytes (no TCP header).
const RAW_HTTP_GET: &[u8] = b"GET /index.html HTTP/1.1\r\n\
Host: example.com\r\n\
User-Agent: Mozilla/5.0 (X11; Linux x86_64)\r\n\
Accept: text/html,application/xhtml+xml\r\n\
Accept-Language: en-US,en;q=0.9\r\n\
Connection: keep-alive\r\n\
\r\n";

/// TLS ClientHello with SNI "test.example.com" (wire format).
///
/// Byte layout (77 bytes total):
///   TLS Record (5): content_type=0x16, version=TLS 1.0, length=72
///   Handshake (4):  type=0x01 (ClientHello), length=68
///   ClientHello:    version=TLS 1.2, random(32), session_id_len=0,
///                   cipher_suites_len=2, [0xc02b], compression=null,
///                   extensions_len=25, SNI extension for "test.example.com"
const RAW_TLS_CLIENT_HELLO: &[u8] = &[
    // TLS Record header
    0x16,       // content_type: Handshake
    0x03, 0x01, // record version: TLS 1.0 (compat)
    0x00, 0x48, // record length: 72
    // Handshake header
    0x01,             // msg_type: ClientHello
    0x00, 0x00, 0x44, // handshake length: 68
    // ClientHello body
    0x03, 0x03, // client version: TLS 1.2
    // random (32 bytes)
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
    0x1e, 0x1f, 0x00, // session_id_len: 0
    0x00, 0x02, // cipher_suites_len: 2
    0xc0, 0x2b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    0x01,       // compression_methods_len: 1
    0x00,       // null compression
    0x00, 0x19, // extensions_len: 25
    // SNI extension (25 bytes)
    0x00, 0x00, // ext_type: server_name (0)
    0x00, 0x15, // ext_data_len: 21
    0x00, 0x13, // server_name_list_len: 19
    0x00,       // name_type: host_name
    0x00, 0x10, // name_len: 16
    // "test.example.com"
    b't', b'e', b's', b't', b'.', b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o',
    b'm',
];

/// Complete Ethernet + IPv4 + TCP SYN frame (54 bytes).
///
/// src=10.0.0.2:49152, dst=10.0.0.1:80, SYN
const ETH_IPV4_TCP_SYN: &[u8] = &[
    // Ethernet header (14 bytes)
    0x00, 0x1c, 0x73, 0x2e, 0x4f, 0xa1, // dst MAC
    0x52, 0x54, 0x00, 0x12, 0x34, 0x56, // src MAC
    0x08, 0x00, // EtherType: IPv4
    // IPv4 header (20 bytes)
    0x45, // version=4, IHL=5
    0x00, // DSCP/ECN
    0x00, 0x28, // total_length: 40 (20 IP + 20 TCP)
    0x1c, 0x46, // identification
    0x40, 0x00, // flags=DF, fragment_offset=0
    0x40, // TTL: 64
    0x06, // protocol: TCP
    0x00, 0x00, // checksum
    0x0a, 0x00, 0x00, 0x02, // src: 10.0.0.2
    0x0a, 0x00, 0x00, 0x01, // dst: 10.0.0.1
    // TCP SYN header (20 bytes)
    0xc0, 0x00, // src_port: 49152
    0x00, 0x50, // dst_port: 80
    0x00, 0x00, 0x00, 0x01, // seq: 1
    0x00, 0x00, 0x00, 0x00, // ack: 0
    0x50, 0x02, // data_offset=5, flags=SYN
    0xff, 0xff, // window: 65535
    0x00, 0x00, // checksum
    0x00, 0x00, // urgent ptr
];

/// Complete Ethernet + IPv4 + UDP + DNS query frame (71 bytes).
///
/// src=10.0.0.2:49152, dst=10.0.0.1:53, query for "example.com" A
const ETH_IPV4_UDP_DNS: &[u8] = &[
    // Ethernet header (14 bytes)
    0x00, 0x1c, 0x73, 0x2e, 0x4f, 0xa1, // dst MAC
    0x52, 0x54, 0x00, 0x12, 0x34, 0x56, // src MAC
    0x08, 0x00, // EtherType: IPv4
    // IPv4 header (20 bytes)
    0x45, // version=4, IHL=5
    0x00, // DSCP/ECN
    0x00, 0x39, // total_length: 57 (20 IP + 8 UDP + 29 DNS)
    0x1c, 0x47, // identification
    0x40, 0x00, // flags=DF, fragment_offset=0
    0x40, // TTL: 64
    0x11, // protocol: UDP
    0x00, 0x00, // checksum
    0x0a, 0x00, 0x00, 0x02, // src: 10.0.0.2
    0x0a, 0x00, 0x00, 0x01, // dst: 10.0.0.1
    // UDP header (8 bytes)
    0xc0, 0x00, // src_port: 49152
    0x00, 0x35, // dst_port: 53
    0x00, 0x25, // length: 37 (8 + 29)
    0x00, 0x00, // checksum
    // DNS query (29 bytes)
    0x12, 0x34, // Transaction ID
    0x01, 0x00, // Flags: standard query, RD=1
    0x00, 0x01, // QDCOUNT: 1
    0x00, 0x00, // ANCOUNT: 0
    0x00, 0x00, // NSCOUNT: 0
    0x00, 0x00, // ARCOUNT: 0
    0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // "example"
    0x03, b'c', b'o', b'm', // "com"
    0x00,       // end of name
    0x00, 0x01, // QTYPE: A
    0x00, 0x01, // QCLASS: IN
];

// ---------------------------------------------------------------------------
// Parser benchmarks
// ---------------------------------------------------------------------------

/// Measure raw TCP header parsing throughput.
fn bench_tcp_parse(c: &mut Criterion) {
    let mut g = c.benchmark_group("parsers");
    g.throughput(Throughput::Elements(1));

    g.bench_function("tcp_parse_syn", |b| {
        b.iter(|| {
            let result = tcp::parse_tcp(black_box(RAW_TCP_SYN));
            black_box(result)
        })
    });

    g.bench_function("tcp_parse_http_payload", |b| {
        b.iter(|| {
            let result = tcp::parse_tcp(black_box(RAW_TCP_HTTP));
            black_box(result)
        })
    });

    g.finish();
}

/// Measure UDP header parsing throughput.
fn bench_udp_parse(c: &mut Criterion) {
    let mut g = c.benchmark_group("parsers");
    g.throughput(Throughput::Elements(1));

    // Build a minimal UDP datagram (header + DNS payload).
    let udp_bytes: Vec<u8> = {
        let mut v = vec![
            0xc0u8, 0x00, // src_port: 49152
            0x00, 0x35, // dst_port: 53
            0x00, 0x25, // length: 37
            0x00, 0x00, // checksum
        ];
        v.extend_from_slice(RAW_DNS_QUERY);
        v
    };

    g.bench_function("udp_parse", |b| {
        b.iter(|| {
            let result = udp::parse_udp(black_box(&udp_bytes));
            black_box(result)
        })
    });

    g.finish();
}

/// Measure DNS wire-format parsing throughput.
fn bench_dns_parse(c: &mut Criterion) {
    let mut g = c.benchmark_group("parsers");
    g.throughput(Throughput::Elements(1));

    g.bench_function("dns_parse_query", |b| {
        b.iter(|| {
            let result = dns::parse_dns(black_box(RAW_DNS_QUERY));
            black_box(result)
        })
    });

    g.finish();
}

/// Measure HTTP/1.x request parsing throughput.
fn bench_http_parse(c: &mut Criterion) {
    let mut g = c.benchmark_group("parsers");
    g.throughput(Throughput::Elements(1));

    g.bench_function("http_parse_get", |b| {
        b.iter(|| {
            let result = http_parser::parse_http(black_box(RAW_HTTP_GET));
            black_box(result)
        })
    });

    g.finish();
}

/// Measure TLS ClientHello + SNI extraction throughput.
fn bench_tls_parse(c: &mut Criterion) {
    let mut g = c.benchmark_group("parsers");
    g.throughput(Throughput::Elements(1));

    g.bench_function("tls_parse_client_hello_sni", |b| {
        b.iter(|| {
            let result = tls::parse_tls_client_hello(black_box(RAW_TLS_CLIENT_HELLO));
            black_box(result)
        })
    });

    g.finish();
}

// ---------------------------------------------------------------------------
// Detector benchmarks
// ---------------------------------------------------------------------------

/// Measure stateless protocol-anomaly detector throughput.
///
/// `check_payload` is called once per packet on the TCP/UDP payload and is on
/// the critical path.  This benchmark shows its per-call cost.
fn bench_proto_anomaly_detector(c: &mut Criterion) {
    let cfg = ProtoAnomalyDetectorConfig::default();
    let det = ProtoAnomalyDetector::new(&cfg);
    let http_payload = RAW_HTTP_GET;

    let mut g = c.benchmark_group("detectors");
    g.throughput(Throughput::Elements(1));

    // HTTP payload on port 80 — expected protocol, should produce no alert.
    g.bench_function("proto_anomaly_http_on_80", |b| {
        b.iter(|| {
            let result = det.check_payload(black_box(http_payload), black_box(80));
            black_box(result)
        })
    });

    // HTTP payload on port 443 — mismatch, should fire an alert.
    g.bench_function("proto_anomaly_http_on_443_mismatch", |b| {
        b.iter(|| {
            let result = det.check_payload(black_box(http_payload), black_box(443));
            black_box(result)
        })
    });

    // TLS payload on port 443 — expected, no alert.
    g.bench_function("proto_anomaly_tls_on_443", |b| {
        b.iter(|| {
            let result =
                det.check_payload(black_box(RAW_TLS_CLIENT_HELLO), black_box(443));
            black_box(result)
        })
    });

    g.finish();
}

/// Measure stateful port-scan detector throughput.
///
/// Each call to `record()` performs a HashMap lookup + insert, which
/// represents the per-packet cost for SYN packets.
fn bench_port_scan_detector(c: &mut Criterion) {
    let cfg = PortScanDetectorConfig::default();
    let mut det = PortScanDetector::new(&cfg);

    let mut g = c.benchmark_group("detectors");
    g.throughput(Throughput::Elements(1));

    // Single fixed source IP scanning sequentially-increasing ports.
    // Below the alert threshold so the detector stays in accumulation mode.
    let mut port: u16 = 1024;
    g.bench_function("port_scan_record_below_threshold", |b| {
        b.iter(|| {
            port = port.wrapping_add(1).max(1024);
            let result = det.record(black_box("10.0.0.99"), black_box(port));
            black_box(result)
        })
    });

    g.finish();
}

// ---------------------------------------------------------------------------
// Full pipeline benchmarks
// ---------------------------------------------------------------------------

/// Process a single complete Ethernet + IPv4 + TCP SYN frame through the
/// full parse stack: Ethernet → IPv4 → TCP → scan-flag checks.
fn bench_pipeline_tcp_syn(c: &mut Criterion) {
    let mut g = c.benchmark_group("pipeline");
    g.throughput(Throughput::Elements(1));

    g.bench_function("eth_ipv4_tcp_syn", |b| {
        b.iter(|| {
            let data = black_box(ETH_IPV4_TCP_SYN);

            let eth = EthernetPacket::new(data).unwrap();
            if eth.get_ethertype() != EtherTypes::Ipv4 {
                return black_box(false);
            }
            let ipv4 = Ipv4Packet::new(eth.payload()).unwrap();
            let is_tcp =
                ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Tcp;
            if !is_tcp {
                return black_box(false);
            }
            let tcp_info = tcp::parse_tcp(ipv4.payload()).unwrap();
            let is_syn = tcp::is_syn_only(&tcp_info);
            black_box(is_syn)
        })
    });

    g.finish();
}

/// Process a single complete Ethernet + IPv4 + UDP + DNS frame through the
/// full parse stack: Ethernet → IPv4 → UDP → DNS.
fn bench_pipeline_udp_dns(c: &mut Criterion) {
    let mut g = c.benchmark_group("pipeline");
    g.throughput(Throughput::Elements(1));

    g.bench_function("eth_ipv4_udp_dns", |b| {
        b.iter(|| {
            let data = black_box(ETH_IPV4_UDP_DNS);

            let eth = EthernetPacket::new(data).unwrap();
            if eth.get_ethertype() != EtherTypes::Ipv4 {
                return black_box(None);
            }
            let ipv4 = Ipv4Packet::new(eth.payload()).unwrap();
            if ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
                return black_box(None);
            }
            let udp_data = ipv4.payload();
            let udp_info = udp::parse_udp(udp_data).unwrap();
            if !udp::is_dns_port(&udp_info) {
                return black_box(None);
            }
            let payload = udp::extract_payload(udp_data);
            let dns_info = dns::parse_dns(payload);
            black_box(dns_info)
        })
    });

    g.finish();
}

/// End-to-end throughput benchmark — processes a large batch of packets and
/// reports aggregate packet rate.
///
/// This is the primary benchmark for the 1–5 Mpps design target.  The loop
/// covers the hot path:
///   1. Ethernet header decode
///   2. IPv4 header decode
///   3. Transport-layer header decode (TCP or UDP alternating)
///   4. Protocol parse (HTTP on TCP, DNS on UDP)
///   5. Protocol-anomaly detector call
///
/// A batch of `BATCH_SIZE` packets is processed per criterion iteration so
/// that the per-packet cost is visible in throughput terms.
fn bench_end_to_end_mpps(c: &mut Criterion) {
    const BATCH_SIZE: u64 = 10_000;

    let cfg_anomaly = ProtoAnomalyDetectorConfig::default();
    let proto_det = ProtoAnomalyDetector::new(&cfg_anomaly);

    let mut g = c.benchmark_group("pipeline");
    // Report throughput as packets per second so that Mpps can be read off
    // directly from the criterion output.
    g.throughput(Throughput::Elements(BATCH_SIZE));

    g.bench_function(
        BenchmarkId::new("end_to_end_mpps", format!("{BATCH_SIZE}_pkts")),
        |b| {
            b.iter(|| {
                let mut processed: u64 = 0;

                for i in 0..BATCH_SIZE {
                    // Alternate between TCP and UDP frames so that both code
                    // paths are exercised equally.
                    let data = if i % 2 == 0 {
                        ETH_IPV4_TCP_SYN
                    } else {
                        ETH_IPV4_UDP_DNS
                    };

                    let eth = match EthernetPacket::new(black_box(data)) {
                        Some(e) => e,
                        None => continue,
                    };
                    if eth.get_ethertype() != EtherTypes::Ipv4 {
                        continue;
                    }
                    let ipv4 = match Ipv4Packet::new(eth.payload()) {
                        Some(ip) => ip,
                        None => continue,
                    };

                    match ipv4.get_next_level_protocol() {
                        IpNextHeaderProtocols::Tcp => {
                            let tcp_data = ipv4.payload();
                            if let Some(info) = tcp::parse_tcp(tcp_data) {
                                let _ = tcp::is_syn_only(&info);
                                if info.payload_len > 0 {
                                    let payload = tcp::parse_tcp_payload(tcp_data, &info);
                                    let _ = http_parser::parse_http(payload);
                                    let _ = proto_det.check_payload(payload, info.dst_port);
                                }
                            }
                        }
                        IpNextHeaderProtocols::Udp => {
                            let udp_data = ipv4.payload();
                            if let Some(info) = udp::parse_udp(udp_data) {
                                if udp::is_dns_port(&info) {
                                    let payload = udp::extract_payload(udp_data);
                                    let _ = dns::parse_dns(payload);
                                }
                                let payload = udp::extract_payload(udp_data);
                                let _ = proto_det.check_payload(payload, info.dst_port);
                            }
                        }
                        _ => {}
                    }

                    processed += 1;
                }

                black_box(processed)
            })
        },
    );

    g.finish();
}

/// Parametric parser scalability: measure parse time for growing batch sizes.
///
/// Verifies that parser cost scales linearly with packet count (no hidden
/// O(n²) allocations or lock contention).
fn bench_parser_scalability(c: &mut Criterion) {
    let mut g = c.benchmark_group("pipeline");

    for batch in [100u64, 1_000, 10_000, 100_000] {
        g.throughput(Throughput::Elements(batch));
        g.bench_with_input(
            BenchmarkId::new("tcp_syn_batch", batch),
            &batch,
            |b, &n| {
                b.iter(|| {
                    let mut ok: u64 = 0;
                    for _ in 0..n {
                        if tcp::parse_tcp(black_box(RAW_TCP_SYN)).is_some() {
                            ok += 1;
                        }
                    }
                    black_box(ok)
                })
            },
        );
    }

    g.finish();
}

// ---------------------------------------------------------------------------
// Criterion wiring
// ---------------------------------------------------------------------------

criterion_group!(
    parser_benches,
    bench_tcp_parse,
    bench_udp_parse,
    bench_dns_parse,
    bench_http_parse,
    bench_tls_parse,
);

criterion_group!(
    detector_benches,
    bench_proto_anomaly_detector,
    bench_port_scan_detector,
);

criterion_group!(
    pipeline_benches,
    bench_pipeline_tcp_syn,
    bench_pipeline_udp_dns,
    bench_end_to_end_mpps,
    bench_parser_scalability,
);

criterion_main!(parser_benches, detector_benches, pipeline_benches);
