//! TLS ClientHello parser — feature 25.7.
//!
//! Extracts the Server Name Indication (SNI) from TLS ClientHello messages
//! to provide visibility into encrypted traffic destinations.
//!
//! # Capabilities
//! - Parses the 5-byte TLS record header (content type, record version, length).
//! - Decodes the Handshake sub-header (type + 3-byte length).
//! - For ClientHello (type 1): walks the extension list and extracts the SNI
//!   hostname from extension type 0x0000 (server_name, RFC 6066).
//! - Provides port and version helper predicates.
//! - Detects suspicious SNI patterns: IP-address literals, oversized names,
//!   and operator-supplied blocklist entries.
//!
//! # Limitations
//! - ClientHello only; ServerHello and post-handshake records yield no SNI.
//! - Single-segment parsing; TLS records split across TCP segments are not
//!   reassembled.
//! - JA3/JA3S fingerprinting is out of scope for this feature.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// TLS content type constants (RFC 5246 §6.2.1 / RFC 8446 §5.1)
// ---------------------------------------------------------------------------

pub const TLS_CONTENT_CHANGE_CIPHER_SPEC: u8 = 20;
pub const TLS_CONTENT_ALERT: u8 = 21;
pub const TLS_CONTENT_HANDSHAKE: u8 = 22;
pub const TLS_CONTENT_APPLICATION_DATA: u8 = 23;
pub const TLS_CONTENT_HEARTBEAT: u8 = 24;

// ---------------------------------------------------------------------------
// TLS handshake type constants (RFC 5246 §7.4 / RFC 8446 §4)
// ---------------------------------------------------------------------------

pub const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 1;
pub const TLS_HANDSHAKE_SERVER_HELLO: u8 = 2;
pub const TLS_HANDSHAKE_CERTIFICATE: u8 = 11;
pub const TLS_HANDSHAKE_SERVER_HELLO_DONE: u8 = 14;
pub const TLS_HANDSHAKE_FINISHED: u8 = 20;

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Extracted TLS metadata from a single TLS record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsInfo {
    /// TLS record content type (22 = Handshake, 23 = ApplicationData, …).
    pub content_type: u8,
    /// Major byte of the record-layer version (always 0x03 for TLS 1.x).
    pub version_major: u8,
    /// Minor byte of the record-layer version (1=TLS 1.0, 2=TLS 1.1, 3=TLS 1.2).
    pub version_minor: u8,
    /// Handshake message type, present only when `content_type` is 22.
    pub handshake_type: Option<u8>,
    /// Server Name Indication hostname, present only in a ClientHello that
    /// carries a valid SNI extension.
    pub sni: Option<String>,
}

// ---------------------------------------------------------------------------
// Public parsing API
// ---------------------------------------------------------------------------

/// Attempt to parse TLS record header and extract SNI from ClientHello.
///
/// This is a best-effort parser that extracts the SNI extension from a TLS
/// ClientHello.  It does **not** perform full TLS parsing.
///
/// Returns `None` if the input is shorter than the 5-byte TLS record header.
/// Returns a [`TlsInfo`] with `sni = None` for all non-ClientHello records
/// (alerts, application data, non-ClientHello handshakes, etc.).
pub fn parse_tls_client_hello(data: &[u8]) -> Option<TlsInfo> {
    // TLS record header: content_type(1) + version(2) + length(2) = 5 bytes.
    if data.len() < 5 {
        return None;
    }

    let content_type = data[0];
    let version_major = data[1];
    let version_minor = data[2];
    let _record_length = u16::from_be_bytes([data[3], data[4]]) as usize;

    // Only Handshake records (content_type = 22) can carry a ClientHello.
    if content_type != TLS_CONTENT_HANDSHAKE {
        return Some(TlsInfo {
            content_type,
            version_major,
            version_minor,
            handshake_type: None,
            sni: None,
        });
    }

    // Handshake type byte starts at offset 5.
    if data.len() < 6 {
        return None;
    }
    let handshake_type = data[5];

    // We only extract SNI from ClientHello (handshake_type = 1).
    if handshake_type != TLS_HANDSHAKE_CLIENT_HELLO {
        return Some(TlsInfo {
            content_type,
            version_major,
            version_minor,
            handshake_type: Some(handshake_type),
            sni: None,
        });
    }

    // Walk the ClientHello body (passed as a slice starting at the handshake
    // type byte) to locate and decode the SNI extension.
    let sni = extract_sni_from_client_hello(&data[5..]);

    Some(TlsInfo {
        content_type,
        version_major,
        version_minor,
        handshake_type: Some(handshake_type),
        sni,
    })
}

// ---------------------------------------------------------------------------
// Version and port helpers
// ---------------------------------------------------------------------------

/// Return a human-readable TLS/SSL version string for the record-layer version
/// bytes found in a TLS record header.
///
/// | major | minor | name         |
/// |-------|-------|--------------|
/// |  0x02 |  0x00 | `"SSL 2.0"`  |
/// |  0x03 |  0x00 | `"SSL 3.0"`  |
/// |  0x03 |  0x01 | `"TLS 1.0"`  |
/// |  0x03 |  0x02 | `"TLS 1.1"`  |
/// |  0x03 |  0x03 | `"TLS 1.2"`  |
/// |  0x03 |  0x04 | `"TLS 1.3"`  |
/// | other |       | `"Unknown"`  |
pub fn tls_version_name(major: u8, minor: u8) -> &'static str {
    match (major, minor) {
        (0x02, 0x00) => "SSL 2.0",
        (0x03, 0x00) => "SSL 3.0",
        (0x03, 0x01) => "TLS 1.0",
        (0x03, 0x02) => "TLS 1.1",
        (0x03, 0x03) => "TLS 1.2",
        (0x03, 0x04) => "TLS 1.3",
        _ => "Unknown",
    }
}

/// Return `true` if `port` is a well-known TLS-wrapped service port.
///
/// Covers: 443 (HTTPS), 465 (SMTPS), 636 (LDAPS), 853 (DoT), 993 (IMAPS),
/// 995 (POP3S), 5671 (AMQPS), 8443 (HTTPS-Alt).
pub fn is_tls_port(port: u16) -> bool {
    matches!(port, 443 | 465 | 636 | 853 | 993 | 995 | 5671 | 8443)
}

/// Return the canonical service name for a well-known TLS port, or `None`.
pub fn tls_service_name(port: u16) -> Option<&'static str> {
    match port {
        443 => Some("HTTPS"),
        465 => Some("SMTPS"),
        636 => Some("LDAPS"),
        853 => Some("DoT"),
        993 => Some("IMAPS"),
        995 => Some("POP3S"),
        5671 => Some("AMQPS"),
        8443 => Some("HTTPS-Alt"),
        _ => None,
    }
}

/// Return a human-readable name for a TLS record content type.
pub fn tls_content_type_name(content_type: u8) -> &'static str {
    match content_type {
        TLS_CONTENT_CHANGE_CIPHER_SPEC => "ChangeCipherSpec",
        TLS_CONTENT_ALERT => "Alert",
        TLS_CONTENT_HANDSHAKE => "Handshake",
        TLS_CONTENT_APPLICATION_DATA => "ApplicationData",
        TLS_CONTENT_HEARTBEAT => "Heartbeat",
        _ => "Unknown",
    }
}

// ---------------------------------------------------------------------------
// SNI suspicion check
// ---------------------------------------------------------------------------

/// Return `true` if the SNI hostname exhibits patterns associated with
/// suspicious or anomalous TLS usage.
///
/// Detection categories:
/// - **IP-address literal as SNI**: RFC 6066 prohibits IP addresses in the
///   `server_name` extension; legitimate clients send hostnames only.
/// - **Oversized hostname**: exceeds the 253-character DNS name limit.
/// - **Empty string**: non-RFC-compliant, likely a fuzzing or probing artefact.
/// - **Blocklist match**: operator-supplied list of known-bad hostnames or
///   domain suffixes.  A match is triggered when the SNI equals a blocklist
///   entry *or* ends with `.<entry>` (subdomain match).
pub fn is_suspicious_sni(sni: &str, blocklist: &[String]) -> bool {
    // Empty SNI is non-standard.
    if sni.is_empty() {
        return true;
    }

    // SNI exceeds maximum DNS name length (RFC 1035 §2.3.4).
    if sni.len() > 253 {
        return true;
    }

    // IP-address literal used as SNI (RFC 6066 §3 prohibits this).
    if is_ip_address(sni) {
        return true;
    }

    // Operator-supplied blocklist (exact or subdomain match).
    for entry in blocklist {
        if sni == entry.as_str() {
            return true;
        }
        // Subdomain match: sni ends with ".<entry>"
        let suffix = format!(".{entry}");
        if sni.ends_with(suffix.as_str()) {
            return true;
        }
    }

    false
}

/// Return `true` if `s` parses as an IPv4 or IPv6 address literal.
///
/// IPv4: four decimal octets separated by dots.
/// IPv6: contains a colon (the canonical marker used before full parsing).
fn is_ip_address(s: &str) -> bool {
    // IPv6 addresses always contain at least one colon.
    if s.contains(':') {
        return true;
    }
    // IPv4: attempt strict parse via the stdlib.
    s.parse::<std::net::Ipv4Addr>().is_ok()
}

// ---------------------------------------------------------------------------
// Internal SNI extraction
// ---------------------------------------------------------------------------

/// Walk a ClientHello handshake message (starting at the handshake type byte)
/// and extract the SNI hostname from extension type 0x0000.
///
/// Returns `None` if no SNI extension is present or if the data is truncated.
fn extract_sni_from_client_hello(handshake: &[u8]) -> Option<String> {
    // Handshake: type(1) + length(3) + client_version(2) + random(32) = 38 bytes minimum.
    if handshake.len() < 38 {
        return None;
    }

    let mut pos: usize = 38; // advance past type + length + client_version + random

    // --- Session ID ----------------------------------------------------------
    if pos >= handshake.len() {
        return None;
    }
    let session_id_len = handshake[pos] as usize;
    pos += 1 + session_id_len;

    // --- Cipher suites -------------------------------------------------------
    if pos + 2 > handshake.len() {
        return None;
    }
    let cipher_suites_len =
        u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;

    // --- Compression methods -------------------------------------------------
    if pos >= handshake.len() {
        return None;
    }
    let comp_len = handshake[pos] as usize;
    pos += 1 + comp_len;

    // --- Extensions ----------------------------------------------------------
    if pos + 2 > handshake.len() {
        return None;
    }
    let extensions_len =
        u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
    pos += 2;

    let extensions_end = pos + extensions_len;
    if extensions_end > handshake.len() {
        return None;
    }

    // Walk extensions looking for SNI (type 0x0000).
    while pos + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]);
        let ext_len =
            u16::from_be_bytes([handshake[pos + 2], handshake[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 {
            // SNI extension found.
            // Format: server_name_list_length(2) + name_type(1) + name_length(2) + name(n)
            if ext_len >= 5 && pos + ext_len <= handshake.len() {
                let name_type = handshake[pos + 2];
                let name_len =
                    u16::from_be_bytes([handshake[pos + 3], handshake[pos + 4]]) as usize;
                if name_type == 0 && pos + 5 + name_len <= handshake.len() {
                    let sni =
                        String::from_utf8_lossy(&handshake[pos + 5..pos + 5 + name_len])
                            .to_string();
                    return Some(sni);
                }
            }
            return None;
        }

        pos += ext_len;
    }

    None
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Helper — build a complete TLS 1.2 ClientHello with an SNI extension.
    //
    // Packet layout (all big-endian):
    //   TLS record header  (5 bytes):
    //     0x16               content_type = Handshake
    //     0x03 0x01          record version = TLS 1.0 (outer record)
    //     record_len (2)     length of the handshake message below
    //
    //   Handshake header   (4 bytes):
    //     0x01               handshake_type = ClientHello
    //     body_len (3)       length of the ClientHello body
    //
    //   ClientHello body:
    //     client_version (2) = 0x03 0x03 (TLS 1.2)
    //     random         (32 zero bytes)
    //     session_id_len (1) = 0
    //     cipher_suites_len (2) = 2
    //     cipher_suite  (2)  = 0x00 0x2F
    //     comp_methods_len (1) = 1
    //     comp_method  (1)   = 0x00 (null)
    //     extensions_len (2) = length of extension block
    //     [ SNI extension ]
    //
    //   SNI extension (type 0x0000):
    //     ext_type  (2)               = 0x00 0x00
    //     ext_len   (2)               = name_type(1) + name_len(2) + name + sni_list_len(2)
    //     sni_list_len (2)            = name_type(1) + name_len(2) + name
    //     name_type (1)               = 0x00 (host_name)
    //     name_len  (2)               = len(sni)
    //     name      (name_len bytes)  = sni bytes
    // -----------------------------------------------------------------------

    fn build_client_hello(sni: &str) -> Vec<u8> {
        let sni_bytes = sni.as_bytes();
        let name_len = sni_bytes.len();

        // SNI extension data (inside ext_len field):
        //   server_name_list_length (2) + name_type (1) + name_length (2) + name (n)
        let sni_list_inner_len = 1 + 2 + name_len; // name_type + name_length + name
        let ext_data_len = 2 + sni_list_inner_len; // sni_list_len field + inner

        // Full extension block: ext_type(2) + ext_len(2) + ext_data(ext_data_len)
        let ext_block_len = 4 + ext_data_len;

        // ClientHello body:
        //   client_version(2) + random(32) + session_id_len(1) +
        //   cipher_suites_len(2) + cipher_suite(2) +
        //   comp_methods_len(1) + comp_method(1) +
        //   extensions_len(2) + extensions(ext_block_len)
        let body_len = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + ext_block_len;

        // Total handshake message = type(1) + length(3) + body(body_len)
        let handshake_len = 1 + 3 + body_len;

        // TLS record = header(5) + handshake(handshake_len)
        let record_len = handshake_len; // record length field covers the handshake message

        let mut pkt = Vec::with_capacity(5 + handshake_len);

        // TLS record header
        pkt.push(TLS_CONTENT_HANDSHAKE); // 0x16
        pkt.push(0x03);
        pkt.push(0x01); // outer record version = TLS 1.0
        pkt.push((record_len >> 8) as u8);
        pkt.push((record_len & 0xFF) as u8);

        // Handshake header
        pkt.push(TLS_HANDSHAKE_CLIENT_HELLO); // 0x01
        pkt.push((body_len >> 16) as u8);
        pkt.push((body_len >> 8) as u8);
        pkt.push((body_len & 0xFF) as u8);

        // ClientHello body
        pkt.push(0x03);
        pkt.push(0x03); // client_version = TLS 1.2
        pkt.extend(std::iter::repeat(0u8).take(32)); // random
        pkt.push(0x00); // session_id_len = 0
        pkt.push(0x00);
        pkt.push(0x02); // cipher_suites_len = 2
        pkt.push(0x00);
        pkt.push(0x2F); // TLS_RSA_WITH_AES_128_CBC_SHA
        pkt.push(0x01); // comp_methods_len = 1
        pkt.push(0x00); // null compression

        // Extensions block length
        pkt.push((ext_block_len >> 8) as u8);
        pkt.push((ext_block_len & 0xFF) as u8);

        // SNI extension
        pkt.push(0x00);
        pkt.push(0x00); // ext_type = 0x0000 (server_name)
        pkt.push((ext_data_len >> 8) as u8);
        pkt.push((ext_data_len & 0xFF) as u8); // ext_len

        // server_name_list_length
        pkt.push((sni_list_inner_len >> 8) as u8);
        pkt.push((sni_list_inner_len & 0xFF) as u8);

        // name_type + name_length + name
        pkt.push(0x00); // name_type = host_name
        pkt.push((name_len >> 8) as u8);
        pkt.push((name_len & 0xFF) as u8);
        pkt.extend_from_slice(sni_bytes);

        pkt
    }

    /// Build a ClientHello with two extensions: an unknown one first, then SNI.
    fn build_client_hello_sni_not_first(sni: &str) -> Vec<u8> {
        let sni_bytes = sni.as_bytes();
        let name_len = sni_bytes.len();

        // Unknown extension: type=0x000F, data=[0xDE, 0xAD]
        let unk_ext: &[u8] = &[0x00, 0x0F, 0x00, 0x02, 0xDE, 0xAD];

        let sni_list_inner_len = 1 + 2 + name_len;
        let ext_data_len = 2 + sni_list_inner_len;
        let sni_ext_len = 4 + ext_data_len;

        let ext_block_len = unk_ext.len() + sni_ext_len;

        let body_len = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + ext_block_len;
        let handshake_len = 1 + 3 + body_len;
        let record_len = handshake_len;

        let mut pkt = Vec::with_capacity(5 + handshake_len);

        pkt.push(TLS_CONTENT_HANDSHAKE);
        pkt.push(0x03);
        pkt.push(0x03); // record version = TLS 1.2
        pkt.push((record_len >> 8) as u8);
        pkt.push((record_len & 0xFF) as u8);

        pkt.push(TLS_HANDSHAKE_CLIENT_HELLO);
        pkt.push((body_len >> 16) as u8);
        pkt.push((body_len >> 8) as u8);
        pkt.push((body_len & 0xFF) as u8);

        pkt.push(0x03);
        pkt.push(0x03);
        pkt.extend(std::iter::repeat(0u8).take(32));
        pkt.push(0x00);
        pkt.push(0x00);
        pkt.push(0x02);
        pkt.push(0x00);
        pkt.push(0x2F);
        pkt.push(0x01);
        pkt.push(0x00);

        pkt.push((ext_block_len >> 8) as u8);
        pkt.push((ext_block_len & 0xFF) as u8);

        // Unknown extension first
        pkt.extend_from_slice(unk_ext);

        // SNI extension second
        pkt.push(0x00);
        pkt.push(0x00);
        pkt.push((ext_data_len >> 8) as u8);
        pkt.push((ext_data_len & 0xFF) as u8);
        pkt.push((sni_list_inner_len >> 8) as u8);
        pkt.push((sni_list_inner_len & 0xFF) as u8);
        pkt.push(0x00);
        pkt.push((name_len >> 8) as u8);
        pkt.push((name_len & 0xFF) as u8);
        pkt.extend_from_slice(sni_bytes);

        pkt
    }

    // -----------------------------------------------------------------------
    // parse_tls_client_hello — minimal record parsing
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_tls_too_short_returns_none() {
        assert!(parse_tls_client_hello(&[]).is_none());
        assert!(parse_tls_client_hello(&[0u8; 4]).is_none());
    }

    #[test]
    fn test_parse_tls_non_handshake_record() {
        // content_type = 0x15 (Alert), not a handshake.
        let data = vec![TLS_CONTENT_ALERT, 0x03, 0x03, 0x00, 0x02];
        let info = parse_tls_client_hello(&data).expect("parse");
        assert_eq!(info.content_type, TLS_CONTENT_ALERT);
        assert!(info.handshake_type.is_none());
        assert!(info.sni.is_none());
    }

    #[test]
    fn test_parse_tls_application_data_record() {
        // content_type = 0x17 (Application Data)
        let data = vec![TLS_CONTENT_APPLICATION_DATA, 0x03, 0x03, 0x00, 0x10];
        let info = parse_tls_client_hello(&data).expect("parse");
        assert_eq!(info.content_type, TLS_CONTENT_APPLICATION_DATA);
        assert_eq!(info.version_major, 0x03);
        assert_eq!(info.version_minor, 0x03);
        assert!(info.handshake_type.is_none());
        assert!(info.sni.is_none());
    }

    #[test]
    fn test_parse_tls_handshake_non_client_hello() {
        // content_type = 0x16 (Handshake), handshake_type = 0x02 (ServerHello)
        let mut data = vec![0u8; 6];
        data[0] = TLS_CONTENT_HANDSHAKE;
        data[1] = 0x03;
        data[2] = 0x03;
        data[5] = TLS_HANDSHAKE_SERVER_HELLO;
        let info = parse_tls_client_hello(&data).expect("parse");
        assert_eq!(info.content_type, TLS_CONTENT_HANDSHAKE);
        assert_eq!(info.handshake_type, Some(TLS_HANDSHAKE_SERVER_HELLO));
        assert!(info.sni.is_none());
    }

    #[test]
    fn test_parse_tls_version_fields() {
        // TLS 1.0 record (major=3, minor=1)
        let data = vec![TLS_CONTENT_ALERT, 0x03, 0x01, 0x00, 0x02];
        let info = parse_tls_client_hello(&data).expect("parse");
        assert_eq!(info.version_major, 0x03);
        assert_eq!(info.version_minor, 0x01);
    }

    #[test]
    fn test_parse_tls_client_hello_without_sni_extension() {
        // ClientHello record that is structurally valid but has no extensions.
        // The parser should return sni = None gracefully.
        let mut data = Vec::new();
        data.push(TLS_CONTENT_HANDSHAKE);
        data.push(0x03);
        data.push(0x03);
        data.push(0x00);
        data.push(0x26); // record_length = 38

        // Handshake header: type(1) + length(3) = 4 bytes
        data.push(TLS_HANDSHAKE_CLIENT_HELLO);
        data.push(0x00);
        data.push(0x00);
        data.push(0x22); // handshake length = 34

        // client_version(2) + random(32) = 34 bytes
        data.push(0x03);
        data.push(0x03);
        data.extend(vec![0u8; 32]);

        // Truncated — no session_id, cipher suites, etc.; SNI lookup fails gracefully.
        let info = parse_tls_client_hello(&data).expect("parse");
        assert_eq!(info.content_type, TLS_CONTENT_HANDSHAKE);
        assert_eq!(info.handshake_type, Some(TLS_HANDSHAKE_CLIENT_HELLO));
        assert!(info.sni.is_none());
    }

    // -----------------------------------------------------------------------
    // SNI extraction — the core of feature 25.7
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_tls_client_hello_extracts_sni() {
        let pkt = build_client_hello("example.com");
        let info = parse_tls_client_hello(&pkt).expect("parse");
        assert_eq!(info.content_type, TLS_CONTENT_HANDSHAKE);
        assert_eq!(info.handshake_type, Some(TLS_HANDSHAKE_CLIENT_HELLO));
        assert_eq!(info.sni.as_deref(), Some("example.com"));
    }

    #[test]
    fn test_parse_tls_client_hello_extracts_subdomain_sni() {
        let pkt = build_client_hello("api.internal.corp.example.com");
        let info = parse_tls_client_hello(&pkt).expect("parse");
        assert_eq!(info.sni.as_deref(), Some("api.internal.corp.example.com"));
    }

    #[test]
    fn test_parse_tls_client_hello_extracts_long_sni() {
        // 63-character label (maximum per RFC 1035)
        let long_sni = format!(
            "{}.example.com",
            "a".repeat(63)
        );
        let pkt = build_client_hello(&long_sni);
        let info = parse_tls_client_hello(&pkt).expect("parse");
        assert_eq!(info.sni.as_deref(), Some(long_sni.as_str()));
    }

    #[test]
    fn test_parse_tls_client_hello_sni_not_first_extension() {
        // SNI is the second extension; the parser must skip the first one.
        let pkt = build_client_hello_sni_not_first("second.example.com");
        let info = parse_tls_client_hello(&pkt).expect("parse");
        assert_eq!(info.sni.as_deref(), Some("second.example.com"));
    }

    #[test]
    fn test_parse_tls_client_hello_record_version_fields() {
        // The outer record uses TLS 1.0 (0x03, 0x01), but the ClientHello
        // client_version field inside the body uses TLS 1.2 (0x03, 0x03).
        // We report the *record-layer* version, not the ClientHello version.
        let pkt = build_client_hello("ver.example.com");
        let info = parse_tls_client_hello(&pkt).expect("parse");
        assert_eq!(info.version_major, 0x03);
        assert_eq!(info.version_minor, 0x01); // outer record = TLS 1.0
    }

    // -----------------------------------------------------------------------
    // tls_version_name
    // -----------------------------------------------------------------------

    #[test]
    fn test_tls_version_name_known_versions() {
        assert_eq!(tls_version_name(0x02, 0x00), "SSL 2.0");
        assert_eq!(tls_version_name(0x03, 0x00), "SSL 3.0");
        assert_eq!(tls_version_name(0x03, 0x01), "TLS 1.0");
        assert_eq!(tls_version_name(0x03, 0x02), "TLS 1.1");
        assert_eq!(tls_version_name(0x03, 0x03), "TLS 1.2");
        assert_eq!(tls_version_name(0x03, 0x04), "TLS 1.3");
    }

    #[test]
    fn test_tls_version_name_unknown() {
        assert_eq!(tls_version_name(0x01, 0x00), "Unknown");
        assert_eq!(tls_version_name(0xFF, 0xFF), "Unknown");
    }

    #[test]
    fn test_tls_version_name_from_parsed_info() {
        let pkt = build_client_hello("v.example.com");
        let info = parse_tls_client_hello(&pkt).expect("parse");
        // The helper should return the right string for the record-layer version.
        let vname = tls_version_name(info.version_major, info.version_minor);
        assert_eq!(vname, "TLS 1.0");
    }

    // -----------------------------------------------------------------------
    // is_tls_port
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_tls_port_standard_ports() {
        assert!(is_tls_port(443));  // HTTPS
        assert!(is_tls_port(465));  // SMTPS
        assert!(is_tls_port(636));  // LDAPS
        assert!(is_tls_port(853));  // DNS over TLS
        assert!(is_tls_port(993));  // IMAPS
        assert!(is_tls_port(995));  // POP3S
        assert!(is_tls_port(5671)); // AMQPS
        assert!(is_tls_port(8443)); // HTTPS-Alt
    }

    #[test]
    fn test_is_tls_port_non_tls_ports() {
        assert!(!is_tls_port(80));   // HTTP (plaintext)
        assert!(!is_tls_port(22));   // SSH
        assert!(!is_tls_port(53));   // DNS (plaintext)
        assert!(!is_tls_port(25));   // SMTP (STARTTLS, not TLS)
        assert!(!is_tls_port(0));
        assert!(!is_tls_port(65535));
    }

    // -----------------------------------------------------------------------
    // tls_service_name
    // -----------------------------------------------------------------------

    #[test]
    fn test_tls_service_name_known_ports() {
        assert_eq!(tls_service_name(443),  Some("HTTPS"));
        assert_eq!(tls_service_name(465),  Some("SMTPS"));
        assert_eq!(tls_service_name(636),  Some("LDAPS"));
        assert_eq!(tls_service_name(853),  Some("DoT"));
        assert_eq!(tls_service_name(993),  Some("IMAPS"));
        assert_eq!(tls_service_name(995),  Some("POP3S"));
        assert_eq!(tls_service_name(5671), Some("AMQPS"));
        assert_eq!(tls_service_name(8443), Some("HTTPS-Alt"));
    }

    #[test]
    fn test_tls_service_name_unknown_ports() {
        assert_eq!(tls_service_name(80),    None);
        assert_eq!(tls_service_name(12345), None);
        assert_eq!(tls_service_name(0),     None);
    }

    // -----------------------------------------------------------------------
    // tls_content_type_name
    // -----------------------------------------------------------------------

    #[test]
    fn test_tls_content_type_name_known_types() {
        assert_eq!(tls_content_type_name(20), "ChangeCipherSpec");
        assert_eq!(tls_content_type_name(21), "Alert");
        assert_eq!(tls_content_type_name(22), "Handshake");
        assert_eq!(tls_content_type_name(23), "ApplicationData");
        assert_eq!(tls_content_type_name(24), "Heartbeat");
        assert_eq!(tls_content_type_name(99), "Unknown");
    }

    // -----------------------------------------------------------------------
    // is_suspicious_sni
    // -----------------------------------------------------------------------

    #[test]
    fn test_suspicious_sni_empty_string() {
        assert!(is_suspicious_sni("", &[]));
    }

    #[test]
    fn test_suspicious_sni_ipv4_address() {
        // RFC 6066 §3 prohibits IP-address literals in the SNI extension.
        assert!(is_suspicious_sni("192.168.1.1", &[]));
        assert!(is_suspicious_sni("10.0.0.1", &[]));
        assert!(is_suspicious_sni("1.2.3.4", &[]));
    }

    #[test]
    fn test_suspicious_sni_ipv6_address() {
        assert!(is_suspicious_sni("::1", &[]));
        assert!(is_suspicious_sni("2001:db8::1", &[]));
    }

    #[test]
    fn test_suspicious_sni_oversized_name() {
        // 254 characters exceeds the 253-char RFC 1035 limit.
        let oversized = "a".repeat(254);
        assert!(is_suspicious_sni(&oversized, &[]));
    }

    #[test]
    fn test_suspicious_sni_exactly_max_length_is_not_suspicious() {
        // 253 characters is the maximum allowed DNS name length.
        let max_len = "a".repeat(253);
        assert!(!is_suspicious_sni(&max_len, &[]));
    }

    #[test]
    fn test_suspicious_sni_blocklist_exact_match() {
        let blocklist = vec!["malware.example.com".to_string()];
        assert!(is_suspicious_sni("malware.example.com", &blocklist));
    }

    #[test]
    fn test_suspicious_sni_blocklist_subdomain_match() {
        let blocklist = vec!["evil.com".to_string()];
        assert!(is_suspicious_sni("c2.evil.com", &blocklist));
        assert!(is_suspicious_sni("stage.c2.evil.com", &blocklist));
    }

    #[test]
    fn test_suspicious_sni_blocklist_no_false_positive() {
        // "notevil.com" must NOT match a blocklist entry of "evil.com".
        let blocklist = vec!["evil.com".to_string()];
        assert!(!is_suspicious_sni("notevil.com", &blocklist));
    }

    #[test]
    fn test_not_suspicious_sni_normal_hostname() {
        assert!(!is_suspicious_sni("example.com", &[]));
        assert!(!is_suspicious_sni("api.example.com", &[]));
        assert!(!is_suspicious_sni("internal.corp", &[]));
    }

    #[test]
    fn test_not_suspicious_sni_empty_blocklist() {
        assert!(!is_suspicious_sni("legit.example.com", &[]));
    }

    // -----------------------------------------------------------------------
    // End-to-end: extract SNI then run suspicion check
    // -----------------------------------------------------------------------

    #[test]
    fn test_e2e_extract_and_check_normal_sni() {
        let pkt = build_client_hello("secure.example.com");
        let info = parse_tls_client_hello(&pkt).expect("parse");
        let sni = info.sni.as_deref().unwrap_or("");
        assert!(!is_suspicious_sni(sni, &[]));
    }

    #[test]
    fn test_e2e_extract_and_check_blocklisted_sni() {
        let pkt = build_client_hello("c2.malicious.net");
        let info = parse_tls_client_hello(&pkt).expect("parse");
        let sni = info.sni.as_deref().unwrap_or("");
        let blocklist = vec!["malicious.net".to_string()];
        assert!(is_suspicious_sni(sni, &blocklist));
    }
}
