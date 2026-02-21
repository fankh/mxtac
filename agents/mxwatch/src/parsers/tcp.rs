//! TCP header parser with option extraction and scan-type detection.
//!
//! Feature 25.4 — Protocol parser: TCP/UDP
//! Parses the full TCP header including variable-length options, classifies
//! connection phases, detects stealth-scan flag patterns, and maps well-known
//! ports to service names.

use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Structs
// ---------------------------------------------------------------------------

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
    /// Parsed TCP options (MSS, window scale, SACK, timestamps).
    #[serde(default)]
    pub options: TcpOptions,
}

/// Decoded TCP flag bits (RFC 793).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
    pub urg: bool,
}

/// Parsed values from the TCP variable-length options region (RFC 793 §3.1).
///
/// Fields are `None` when the corresponding option is absent.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TcpOptions {
    /// Maximum Segment Size (option kind 2); typically present only in SYN segments.
    pub mss: Option<u16>,
    /// Window scale exponent (option kind 3); effective window = window << scale.
    pub window_scale: Option<u8>,
    /// SACK (Selective Acknowledgement) permitted (option kind 4).
    pub sack_permitted: bool,
    /// TCP Timestamp `(TSval, TSecr)` pair (option kind 8).
    pub timestamps: Option<(u32, u32)>,
}

/// High-level classification of a TCP segment's connection phase.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TcpConnectionPhase {
    /// SYN only — active open / connection initiation.
    Opening,
    /// SYN + ACK — passive open response.
    SynAck,
    /// ACK only (no SYN, FIN, RST) — data transfer in progress.
    Established,
    /// FIN set — orderly connection teardown initiated.
    Closing,
    /// RST set — connection abruptly reset.
    Reset,
    /// Unusual flag combination consistent with stealth scan techniques
    /// (e.g. XMAS scan, NULL scan).
    ScanLikely,
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse a TCP header and options from a raw byte slice.
///
/// Returns `None` if `data` is shorter than the minimum 20-byte TCP header.
pub fn parse_tcp(data: &[u8]) -> Option<TcpInfo> {
    let pkt = TcpPacket::new(data)?;
    let flags_raw = pkt.get_flags();

    // Extract options from the variable-length header region.
    let data_offset_bytes = (pkt.get_data_offset() as usize).saturating_mul(4);
    let options = if data_offset_bytes > 20 {
        let opts_end = data_offset_bytes.min(data.len());
        if opts_end > 20 {
            parse_tcp_options(&data[20..opts_end])
        } else {
            TcpOptions::default()
        }
    } else {
        TcpOptions::default()
    };

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
        options,
    })
}

/// Parse TCP options from the raw option bytes between the fixed 20-byte header
/// and the TCP payload.
///
/// `opts` should be the slice `raw_tcp_data[20..data_offset_bytes]`.
///
/// Silently skips malformed or unknown options; unknown kinds are consumed via
/// their `length` field so parsing continues where possible.
pub fn parse_tcp_options(opts: &[u8]) -> TcpOptions {
    let mut result = TcpOptions::default();
    let mut i = 0;

    while i < opts.len() {
        match opts[i] {
            0 => break, // EOL — end of options list
            1 => {
                // NOP — single-byte padding, no length field
                i += 1;
            }
            kind => {
                // All multi-byte options have a length field at i+1.
                if i + 1 >= opts.len() {
                    break; // malformed: no room for length byte
                }
                let len = opts[i + 1] as usize;
                if len < 2 || i + len > opts.len() {
                    break; // malformed: length out of bounds
                }
                match kind {
                    2 if len == 4 => {
                        // MSS: kind(1) + length(1) + mss(2)
                        result.mss =
                            Some(u16::from_be_bytes([opts[i + 2], opts[i + 3]]));
                    }
                    3 if len == 3 => {
                        // Window Scale: kind(1) + length(1) + shift_count(1)
                        result.window_scale = Some(opts[i + 2]);
                    }
                    4 if len == 2 => {
                        // SACK Permitted: kind(1) + length(1)
                        result.sack_permitted = true;
                    }
                    8 if len == 10 => {
                        // Timestamps: kind(1) + length(1) + TSval(4) + TSecr(4)
                        let tsval = u32::from_be_bytes([
                            opts[i + 2],
                            opts[i + 3],
                            opts[i + 4],
                            opts[i + 5],
                        ]);
                        let tsecr = u32::from_be_bytes([
                            opts[i + 6],
                            opts[i + 7],
                            opts[i + 8],
                            opts[i + 9],
                        ]);
                        result.timestamps = Some((tsval, tsecr));
                    }
                    _ => {} // unknown or unsupported — skip via length field
                }
                i += len;
            }
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Payload helper
// ---------------------------------------------------------------------------

/// Return a sub-slice containing only the TCP payload bytes from the raw
/// TCP segment `data`.
///
/// This is a zero-copy helper that uses the pre-computed `payload_len` from
/// a [`TcpInfo`] to avoid re-parsing the header.
pub fn parse_tcp_payload<'a>(data: &'a [u8], info: &TcpInfo) -> &'a [u8] {
    let start = data.len().saturating_sub(info.payload_len);
    &data[start..]
}

// ---------------------------------------------------------------------------
// Flag / scan classification helpers
// ---------------------------------------------------------------------------

/// Return `true` if SYN is set and ACK is clear (connection initiation probe).
pub fn is_syn_only(info: &TcpInfo) -> bool {
    info.flags.syn && !info.flags.ack
}

/// Return `true` if all three XMAS-scan flag bits (FIN, URG, PSH) are set.
///
/// XMAS scans exploit RFC 793 closed-port behaviour; open ports on many OS
/// implementations silently discard the packet without responding.
pub fn is_xmas_scan(info: &TcpInfo) -> bool {
    info.flags.fin && info.flags.urg && info.flags.psh
}

/// Return `true` if no control flags are set (NULL scan / stealth probe).
///
/// Like XMAS scans, NULL scans rely on RFC 793 behaviour where closed ports
/// respond with RST while open ports do not respond.
pub fn is_null_scan(info: &TcpInfo) -> bool {
    let f = &info.flags;
    !f.syn && !f.ack && !f.fin && !f.rst && !f.psh && !f.urg
}

/// Return `true` if only the FIN flag is set (FIN/Stealth FIN scan).
pub fn is_fin_scan(info: &TcpInfo) -> bool {
    let f = &info.flags;
    f.fin && !f.syn && !f.ack && !f.rst && !f.psh && !f.urg
}

/// Classify the connection phase from the parsed flag set.
pub fn classify_connection_phase(info: &TcpInfo) -> TcpConnectionPhase {
    let f = &info.flags;

    if f.rst {
        return TcpConnectionPhase::Reset;
    }
    if f.syn && !f.ack {
        return TcpConnectionPhase::Opening;
    }
    if f.syn && f.ack {
        return TcpConnectionPhase::SynAck;
    }

    // Stealth-scan flag patterns must be checked before generic FIN/ACK
    // classification because XMAS scan sets FIN alongside URG+PSH.
    let any_flag = f.syn || f.ack || f.fin || f.rst || f.psh || f.urg;
    if !any_flag {
        return TcpConnectionPhase::ScanLikely; // NULL scan (no flags set)
    }
    if f.fin && f.urg && f.psh {
        return TcpConnectionPhase::ScanLikely; // XMAS scan (FIN+URG+PSH)
    }

    if f.fin {
        return TcpConnectionPhase::Closing;
    }

    TcpConnectionPhase::Established
}

// ---------------------------------------------------------------------------
// Service name mapping
// ---------------------------------------------------------------------------

/// Return a well-known service name for a TCP port number, or `None` for
/// unknown / ephemeral ports.
pub fn service_name_for_port(port: u16) -> Option<&'static str> {
    match port {
        20 | 21 => Some("FTP"),
        22 => Some("SSH"),
        23 => Some("Telnet"),
        25 => Some("SMTP"),
        53 => Some("DNS"),
        80 => Some("HTTP"),
        110 => Some("POP3"),
        143 => Some("IMAP"),
        443 => Some("HTTPS"),
        445 => Some("SMB"),
        3306 => Some("MySQL"),
        3389 => Some("RDP"),
        5432 => Some("PostgreSQL"),
        6379 => Some("Redis"),
        8080 => Some("HTTP-Alt"),
        8443 => Some("HTTPS-Alt"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid 20-byte TCP header (no options).
    ///
    /// Layout (RFC 793):
    ///   src_port(2) dst_port(2) seq(4) ack(4)
    ///   data_offset+flags(2) window(2) checksum(2) urgent(2)
    fn make_tcp_header(src_port: u16, dst_port: u16, flags: u8) -> Vec<u8> {
        let mut h = vec![0u8; 20];
        h[0] = (src_port >> 8) as u8;
        h[1] = (src_port & 0xFF) as u8;
        h[2] = (dst_port >> 8) as u8;
        h[3] = (dst_port & 0xFF) as u8;
        // data_offset = 5 (20 bytes), reserved = 0, NS = 0
        h[12] = 0x50;
        h[13] = flags;
        // window = 65535
        h[14] = 0xFF;
        h[15] = 0xFF;
        h
    }

    /// Build a TCP header with appended options.
    ///
    /// The options bytes are placed after the fixed 20-byte header; the total
    /// header is rounded up to a 4-byte boundary and `data_offset` is set
    /// accordingly.
    fn make_tcp_header_with_options(
        src_port: u16,
        dst_port: u16,
        flags: u8,
        opts: &[u8],
    ) -> Vec<u8> {
        let raw_opts_len = opts.len();
        let padded_opts_len = (raw_opts_len + 3) & !3; // round up to 4-byte boundary
        let data_offset = (20 + padded_opts_len) / 4; // in 32-bit words
        let mut h = vec![0u8; 20 + padded_opts_len];
        h[0] = (src_port >> 8) as u8;
        h[1] = (src_port & 0xFF) as u8;
        h[2] = (dst_port >> 8) as u8;
        h[3] = (dst_port & 0xFF) as u8;
        h[12] = (data_offset as u8) << 4; // upper nibble = data_offset
        h[13] = flags;
        h[14] = 0xFF;
        h[15] = 0xFF;
        h[20..20 + raw_opts_len].copy_from_slice(opts);
        h
    }

    // -----------------------------------------------------------------------
    // parse_tcp — basic header
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

    // -----------------------------------------------------------------------
    // Stealth scan detection helpers
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_xmas_scan() {
        // FIN(0x01) + PSH(0x08) + URG(0x20) = 0x29
        let hdr = make_tcp_header(4321, 80, 0x29);
        let info = parse_tcp(&hdr).expect("parse");
        assert!(is_xmas_scan(&info), "should detect XMAS scan flags");
        assert!(!is_null_scan(&info));
        assert!(!is_fin_scan(&info));
    }

    #[test]
    fn test_is_null_scan() {
        let hdr = make_tcp_header(4321, 80, 0x00); // no flags
        let info = parse_tcp(&hdr).expect("parse");
        assert!(is_null_scan(&info), "should detect NULL scan");
        assert!(!is_xmas_scan(&info));
        assert!(!is_fin_scan(&info));
    }

    #[test]
    fn test_is_fin_scan() {
        let hdr = make_tcp_header(4321, 80, 0x01); // FIN only
        let info = parse_tcp(&hdr).expect("parse");
        assert!(is_fin_scan(&info), "should detect FIN scan");
        assert!(!is_null_scan(&info));
        assert!(!is_xmas_scan(&info));
    }

    #[test]
    fn test_normal_ack_is_not_a_scan() {
        let hdr = make_tcp_header(80, 1024, 0x10); // ACK only
        let info = parse_tcp(&hdr).expect("parse");
        assert!(!is_xmas_scan(&info));
        assert!(!is_null_scan(&info));
        assert!(!is_fin_scan(&info));
    }

    // -----------------------------------------------------------------------
    // classify_connection_phase
    // -----------------------------------------------------------------------

    #[test]
    fn test_classify_phase_opening() {
        let hdr = make_tcp_header(1024, 80, 0x02); // SYN
        let info = parse_tcp(&hdr).expect("parse");
        assert_eq!(classify_connection_phase(&info), TcpConnectionPhase::Opening);
    }

    #[test]
    fn test_classify_phase_syn_ack() {
        let hdr = make_tcp_header(80, 1024, 0x12); // SYN+ACK
        let info = parse_tcp(&hdr).expect("parse");
        assert_eq!(classify_connection_phase(&info), TcpConnectionPhase::SynAck);
    }

    #[test]
    fn test_classify_phase_established() {
        let hdr = make_tcp_header(80, 1024, 0x10); // ACK
        let info = parse_tcp(&hdr).expect("parse");
        assert_eq!(
            classify_connection_phase(&info),
            TcpConnectionPhase::Established
        );
    }

    #[test]
    fn test_classify_phase_closing() {
        let hdr = make_tcp_header(80, 1024, 0x11); // FIN+ACK
        let info = parse_tcp(&hdr).expect("parse");
        assert_eq!(classify_connection_phase(&info), TcpConnectionPhase::Closing);
    }

    #[test]
    fn test_classify_phase_reset() {
        let hdr = make_tcp_header(80, 1024, 0x04); // RST
        let info = parse_tcp(&hdr).expect("parse");
        assert_eq!(classify_connection_phase(&info), TcpConnectionPhase::Reset);
    }

    #[test]
    fn test_classify_phase_null_scan() {
        let hdr = make_tcp_header(4321, 80, 0x00); // no flags
        let info = parse_tcp(&hdr).expect("parse");
        assert_eq!(
            classify_connection_phase(&info),
            TcpConnectionPhase::ScanLikely
        );
    }

    #[test]
    fn test_classify_phase_xmas_scan() {
        let hdr = make_tcp_header(4321, 80, 0x29); // FIN+PSH+URG
        let info = parse_tcp(&hdr).expect("parse");
        assert_eq!(
            classify_connection_phase(&info),
            TcpConnectionPhase::ScanLikely
        );
    }

    // -----------------------------------------------------------------------
    // TCP options parsing
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_tcp_options_mss() {
        // kind=2, length=4, mss=1460 (0x05B4)
        let opts = [0x02u8, 0x04, 0x05, 0xB4];
        let result = parse_tcp_options(&opts);
        assert_eq!(result.mss, Some(1460));
        assert_eq!(result.window_scale, None);
        assert!(!result.sack_permitted);
        assert_eq!(result.timestamps, None);
    }

    #[test]
    fn test_parse_tcp_options_window_scale() {
        // kind=3, length=3, shift=7
        let opts = [0x03u8, 0x03, 0x07];
        let result = parse_tcp_options(&opts);
        assert_eq!(result.window_scale, Some(7));
    }

    #[test]
    fn test_parse_tcp_options_sack_permitted() {
        // kind=4, length=2
        let opts = [0x04u8, 0x02];
        let result = parse_tcp_options(&opts);
        assert!(result.sack_permitted);
    }

    #[test]
    fn test_parse_tcp_options_timestamps() {
        // kind=8, length=10, TSval=0x00010203, TSecr=0x04050607
        let opts = [
            0x08u8, 0x0A, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        ];
        let result = parse_tcp_options(&opts);
        assert_eq!(result.timestamps, Some((0x00010203, 0x04050607)));
    }

    #[test]
    fn test_parse_tcp_options_nop_padding() {
        // NOP + NOP + MSS
        let opts = [0x01u8, 0x01, 0x02, 0x04, 0x05, 0xB4];
        let result = parse_tcp_options(&opts);
        assert_eq!(result.mss, Some(1460));
    }

    #[test]
    fn test_parse_tcp_options_combined_syn_opts() {
        // Typical Linux SYN options:
        // MSS(4) + SACK-permitted(2) + NOP+NOP + Timestamps(10) + NOP + WScale(3)
        let opts: &[u8] = &[
            0x02, 0x04, 0x05, 0xB4, // MSS = 1460
            0x04, 0x02, // SACK permitted
            0x01, 0x01, // NOP, NOP
            0x08, 0x0A, 0x00, 0x00, 0x03, 0xE8, 0x00, 0x00, 0x00, 0x00, // TS
            0x01, // NOP
            0x03, 0x03, 0x06, // Window scale = 6
        ];
        let result = parse_tcp_options(opts);
        assert_eq!(result.mss, Some(1460));
        assert!(result.sack_permitted);
        assert_eq!(result.timestamps, Some((1000, 0)));
        assert_eq!(result.window_scale, Some(6));
    }

    #[test]
    fn test_parse_tcp_options_eol_stops_parsing() {
        // EOL (0x00) must terminate option processing even with data following.
        let opts = [0x00u8, 0x02, 0x04, 0x05, 0xB4];
        let result = parse_tcp_options(&opts);
        assert_eq!(result.mss, None);
    }

    #[test]
    fn test_parse_tcp_options_malformed_truncated() {
        // MSS declared as length=4 but only 3 bytes remain — must fail gracefully.
        let opts = [0x02u8, 0x04, 0x05]; // only 3 bytes instead of 4
        let result = parse_tcp_options(&opts);
        assert_eq!(result.mss, None);
    }

    #[test]
    fn test_parse_tcp_header_with_mss_option() {
        // Full TCP header (24 bytes) with 4-byte MSS option.
        let opts = [0x02u8, 0x04, 0x05, 0xB4]; // MSS = 1460
        let hdr = make_tcp_header_with_options(1024, 443, 0x02, &opts); // SYN
        let info = parse_tcp(&hdr).expect("parse");
        assert_eq!(info.src_port, 1024);
        assert_eq!(info.dst_port, 443);
        assert!(info.flags.syn);
        assert_eq!(info.options.mss, Some(1460));
    }

    // -----------------------------------------------------------------------
    // parse_tcp_payload
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_tcp_payload_extracts_data() {
        let mut hdr = make_tcp_header(80, 1024, 0x18); // PSH+ACK
        hdr.extend_from_slice(b"HTTP/1.1 200 OK\r\n");
        let info = parse_tcp(&hdr).expect("parse");
        let payload = parse_tcp_payload(&hdr, &info);
        assert_eq!(payload, b"HTTP/1.1 200 OK\r\n");
    }

    #[test]
    fn test_parse_tcp_payload_empty_for_no_data() {
        let hdr = make_tcp_header(1024, 80, 0x02); // SYN, no payload
        let info = parse_tcp(&hdr).expect("parse");
        let payload = parse_tcp_payload(&hdr, &info);
        assert!(payload.is_empty());
    }

    // -----------------------------------------------------------------------
    // service_name_for_port
    // -----------------------------------------------------------------------

    #[test]
    fn test_service_name_for_port_known() {
        assert_eq!(service_name_for_port(22), Some("SSH"));
        assert_eq!(service_name_for_port(80), Some("HTTP"));
        assert_eq!(service_name_for_port(443), Some("HTTPS"));
        assert_eq!(service_name_for_port(3306), Some("MySQL"));
        assert_eq!(service_name_for_port(3389), Some("RDP"));
        assert_eq!(service_name_for_port(6379), Some("Redis"));
    }

    #[test]
    fn test_service_name_for_port_unknown() {
        assert_eq!(service_name_for_port(12345), None);
        assert_eq!(service_name_for_port(0), None);
        assert_eq!(service_name_for_port(65535), None);
    }
}
