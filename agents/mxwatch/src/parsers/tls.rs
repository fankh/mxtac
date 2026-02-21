//! Minimal TLS ClientHello parser.
//!
//! Extracts the Server Name Indication (SNI) from TLS ClientHello messages
//! to provide visibility into encrypted traffic destinations.

use serde::{Deserialize, Serialize};

/// Extracted TLS metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsInfo {
    pub content_type: u8,
    pub version_major: u8,
    pub version_minor: u8,
    pub handshake_type: Option<u8>,
    pub sni: Option<String>,
}

/// Attempt to parse TLS record header and extract SNI from ClientHello.
///
/// This is a best-effort parser for extracting the SNI extension from
/// a TLS ClientHello. It does NOT perform full TLS parsing.
pub fn parse_tls_client_hello(data: &[u8]) -> Option<TlsInfo> {
    // TLS record header: content_type(1) + version(2) + length(2) = 5 bytes
    if data.len() < 5 {
        return None;
    }

    let content_type = data[0];
    let version_major = data[1];
    let version_minor = data[2];
    let _record_length = u16::from_be_bytes([data[3], data[4]]) as usize;

    // We only care about Handshake records (content_type = 22).
    if content_type != 22 {
        return Some(TlsInfo {
            content_type,
            version_major,
            version_minor,
            handshake_type: None,
            sni: None,
        });
    }

    // Handshake header starts at offset 5.
    if data.len() < 6 {
        return None;
    }
    let handshake_type = data[5];

    // ClientHello = handshake_type 1
    if handshake_type != 1 {
        return Some(TlsInfo {
            content_type,
            version_major,
            version_minor,
            handshake_type: Some(handshake_type),
            sni: None,
        });
    }

    // Try to locate the SNI extension by scanning for the extension type 0x0000.
    let sni = extract_sni_from_client_hello(&data[5..]);

    Some(TlsInfo {
        content_type,
        version_major,
        version_minor,
        handshake_type: Some(handshake_type),
        sni,
    })
}

/// Brute-force search for the SNI extension (type 0x0000) inside a
/// ClientHello handshake message.
fn extract_sni_from_client_hello(handshake: &[u8]) -> Option<String> {
    // Handshake: type(1) + length(3) + client_version(2) + random(32) = 38 bytes minimum
    if handshake.len() < 38 {
        return None;
    }

    let mut pos: usize = 38; // skip to session_id

    // Session ID
    if pos >= handshake.len() {
        return None;
    }
    let session_id_len = handshake[pos] as usize;
    pos += 1 + session_id_len;

    // Cipher suites
    if pos + 2 > handshake.len() {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;

    // Compression methods
    if pos >= handshake.len() {
        return None;
    }
    let comp_len = handshake[pos] as usize;
    pos += 1 + comp_len;

    // Extensions length
    if pos + 2 > handshake.len() {
        return None;
    }
    let extensions_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
    pos += 2;

    let extensions_end = pos + extensions_len;
    if extensions_end > handshake.len() {
        return None;
    }

    // Walk through extensions looking for SNI (type 0x0000).
    while pos + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]);
        let ext_len = u16::from_be_bytes([handshake[pos + 2], handshake[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 {
            // SNI extension found. Parse the server name list.
            if ext_len >= 5 && pos + ext_len <= handshake.len() {
                // server_name_list_length(2) + name_type(1) + name_length(2)
                let name_type = handshake[pos + 2];
                let name_len =
                    u16::from_be_bytes([handshake[pos + 3], handshake[pos + 4]]) as usize;
                if name_type == 0 && pos + 5 + name_len <= handshake.len() {
                    let sni = String::from_utf8_lossy(&handshake[pos + 5..pos + 5 + name_len])
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
        let data = vec![0x15, 0x03, 0x03, 0x00, 0x02];
        let info = parse_tls_client_hello(&data).expect("parse");
        assert_eq!(info.content_type, 0x15);
        assert!(info.handshake_type.is_none());
        assert!(info.sni.is_none());
    }

    #[test]
    fn test_parse_tls_application_data_record() {
        // content_type = 0x17 (Application Data)
        let data = vec![0x17, 0x03, 0x03, 0x00, 0x10];
        let info = parse_tls_client_hello(&data).expect("parse");
        assert_eq!(info.content_type, 0x17);
        assert_eq!(info.version_major, 0x03);
        assert_eq!(info.version_minor, 0x03);
        assert!(info.handshake_type.is_none());
        assert!(info.sni.is_none());
    }

    #[test]
    fn test_parse_tls_handshake_non_client_hello() {
        // content_type = 0x16 (Handshake), handshake_type = 0x02 (ServerHello)
        let mut data = vec![0u8; 6];
        data[0] = 0x16; // Handshake
        data[1] = 0x03; // TLS 1.2
        data[2] = 0x03;
        data[4] = 0x00; // record length (not validated deeply)
        data[5] = 0x02; // ServerHello
        let info = parse_tls_client_hello(&data).expect("parse");
        assert_eq!(info.content_type, 0x16);
        assert_eq!(info.handshake_type, Some(0x02));
        assert!(info.sni.is_none());
    }

    #[test]
    fn test_parse_tls_version_fields() {
        // TLS 1.0 record (major=3, minor=1)
        let data = vec![0x15, 0x03, 0x01, 0x00, 0x02];
        let info = parse_tls_client_hello(&data).expect("parse");
        assert_eq!(info.version_major, 0x03);
        assert_eq!(info.version_minor, 0x01);
    }

    #[test]
    fn test_parse_tls_client_hello_without_sni_extension() {
        // ClientHello record that is valid structurally but has no extensions
        // (session_id=0, cipher_suites=2 bytes, comp=1 byte, no extensions).
        // This is truncated/incomplete for SNI extraction — sni should be None.
        let mut data = Vec::new();
        data.push(0x16); // Handshake
        data.push(0x03);
        data.push(0x03); // TLS 1.2
        data.push(0x00); // record_length hi
        data.push(0x26); // record_length lo = 38

        // Handshake header: type(1) + length(3) = 4 bytes
        data.push(0x01); // ClientHello
        data.push(0x00);
        data.push(0x00);
        data.push(0x22); // handshake length = 34

        // client_version(2) + random(32) = 34 bytes
        data.push(0x03);
        data.push(0x03);
        data.extend(vec![0u8; 32]); // random

        // No session_id, cipher suites, etc. (truncated — SNI lookup fails gracefully)

        let info = parse_tls_client_hello(&data).expect("parse");
        assert_eq!(info.content_type, 0x16);
        assert_eq!(info.handshake_type, Some(0x01));
        assert!(info.sni.is_none()); // no extensions → no SNI
    }
}
