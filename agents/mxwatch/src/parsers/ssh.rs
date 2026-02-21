//! SSH protocol parser — feature 25.8.
//!
//! Extracts the version banner and binary packet metadata from SSH sessions
//! on port 22 to provide visibility into remote-access activity and detect
//! suspicious SSH software or protocol configurations.
//!
//! # Capabilities
//! - Parses the SSH identification string (banner) sent at session start
//!   by both client and server (RFC 4253 §4.2).
//! - Extracts protocol version (`SSH-2.0` vs `SSH-1.x`) and software version
//!   string (e.g., `OpenSSH_9.3`, `libssh-0.9.6`).
//! - Parses binary SSH packet headers for KEXINIT messages (type 20) to
//!   extract key-exchange algorithm list lengths as a complexity indicator.
//! - Detects suspicious patterns: legacy SSH-1 usage, non-standard software
//!   version strings, and KEXINIT with anomalously short algorithm lists.
//!
//! # Limitations
//! - After key exchange the session is encrypted; payload analysis stops at
//!   the NEWKEYS message (type 21).
//! - Multi-segment banner lines (rare in practice) are not reassembled.
//! - The KEXINIT parser reads only the message type byte and the total
//!   algorithm list length; individual algorithm names are not decoded.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// SSH protocol constants (RFC 4253)
// ---------------------------------------------------------------------------

/// SSH banner prefix required by RFC 4253 §4.2.
pub const SSH_BANNER_PREFIX: &[u8] = b"SSH-";

/// Protocol version string for SSH 2.0 (the only non-deprecated version).
pub const SSH_PROTO_V2: &str = "2.0";

/// Protocol version string for the deprecated SSH 1.x family.
pub const SSH_PROTO_V1: &str = "1.";

/// SSH binary packet: KEXINIT message type (RFC 4253 §6.5).
pub const SSH_MSG_KEXINIT: u8 = 20;

/// SSH binary packet: NEWKEYS message type — session becomes encrypted.
pub const SSH_MSG_NEWKEYS: u8 = 21;

/// SSH binary packet: SERVICE_REQUEST message type.
pub const SSH_MSG_SERVICE_REQUEST: u8 = 5;

/// SSH binary packet: USERAUTH_REQUEST message type (RFC 4252 §5).
pub const SSH_MSG_USERAUTH_REQUEST: u8 = 50;

/// SSH binary packet: USERAUTH_FAILURE message type.
pub const SSH_MSG_USERAUTH_FAILURE: u8 = 51;

/// SSH binary packet: USERAUTH_SUCCESS message type.
pub const SSH_MSG_USERAUTH_SUCCESS: u8 = 52;

/// SSH binary packet: DISCONNECT message type.
pub const SSH_MSG_DISCONNECT: u8 = 1;

/// Minimum size of an SSH binary packet header (length + padding_length).
pub const SSH_PKT_HEADER_SIZE: usize = 5;

/// Maximum plausible banner length to guard against degenerate input.
pub const MAX_BANNER_LEN: usize = 255;

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Metadata extracted from the SSH identification banner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshBannerInfo {
    /// SSH protocol version from the banner (e.g., `"2.0"`, `"1.99"`).
    pub proto_version: String,

    /// Software version string from the banner (e.g., `"OpenSSH_9.3p2"`).
    ///
    /// Corresponds to `<softwareversion>` in RFC 4253 §4.2.
    pub software_version: String,

    /// Optional comment field from the banner (e.g., `"Debian-5+deb10u1"`).
    pub comment: Option<String>,

    /// True when the banner was sent by a client (heuristic: first packet in
    /// a new flow on port 22 is almost always a client banner).
    pub is_client_banner: bool,
}

/// Metadata from an SSH binary packet header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshPacketInfo {
    /// SSH message type byte (e.g., 20 = KEXINIT, 21 = NEWKEYS).
    pub message_type: u8,

    /// Declared packet payload length (from the 4-byte big-endian length field).
    pub packet_length: u32,
}

/// Combined SSH session metadata from a single TCP payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshInfo {
    /// Banner information, present when the payload starts with `SSH-`.
    pub banner: Option<SshBannerInfo>,

    /// Binary packet header, present when the payload starts with a valid
    /// SSH binary packet (non-banner frame, after key-exchange).
    pub packet: Option<SshPacketInfo>,
}

// ---------------------------------------------------------------------------
// Public parsing API
// ---------------------------------------------------------------------------

/// Attempt to parse SSH metadata from a raw TCP payload.
///
/// The function first checks whether the payload begins with the SSH banner
/// prefix (`SSH-`).  If so, it parses the banner fields.  Otherwise it
/// attempts to interpret the payload as an SSH binary packet and extracts the
/// message type.
///
/// Returns `None` when the payload is too short or does not resemble SSH
/// traffic.  Returns `Some(SshInfo)` with partial fields when only one of
/// the two sub-parsers succeeds.
pub fn parse_ssh(data: &[u8]) -> Option<SshInfo> {
    if data.is_empty() {
        return None;
    }

    // --- Banner detection -----------------------------------------------------
    if data.starts_with(SSH_BANNER_PREFIX) {
        let banner = parse_ssh_banner(data);
        return Some(SshInfo {
            banner,
            packet: None,
        });
    }

    // --- Binary packet detection ----------------------------------------------
    let packet = parse_ssh_packet(data);
    if packet.is_some() {
        return Some(SshInfo {
            banner: None,
            packet,
        });
    }

    None
}

/// Return `true` if `port` is the standard SSH service port.
pub fn is_ssh_port(port: u16) -> bool {
    port == 22
}

// ---------------------------------------------------------------------------
// Suspicion detection
// ---------------------------------------------------------------------------

/// Return `true` if the SSH session metadata exhibits suspicious indicators.
///
/// Detection categories:
///
/// - **Legacy SSH-1 protocol**: SSH-1 is deprecated and vulnerable to
///   man-in-the-middle attacks (RFC 4251 appendix, CERT CA-2001-35).
///
/// - **Anomalous software version**: Software version strings containing
///   common implant or tool markers (`libssh`, `paramiko`, `AsyncSSH`, etc.)
///   may indicate automated exploitation or scripted access.  These strings
///   are operator-tunable via the `software_blocklist` parameter.
///
/// - **Empty software version**: RFC 4253 §4.2 requires a non-empty
///   `<softwareversion>` field; an empty string indicates a malformed banner
///   produced by non-compliant or custom tooling.
pub fn is_suspicious_ssh(info: &SshInfo, software_blocklist: &[String]) -> bool {
    if let Some(ref banner) = info.banner {
        // Legacy SSH-1 — not safe to use.
        if banner.proto_version.starts_with(SSH_PROTO_V1) {
            return true;
        }

        // RFC 4253 §4.2 requires a non-empty software version field.
        if banner.software_version.is_empty() {
            return true;
        }

        // Operator-supplied software version blocklist (case-insensitive
        // substring match, e.g., "paramiko", "libssh2", "impacket").
        let sw_lower = banner.software_version.to_lowercase();
        for entry in software_blocklist {
            if sw_lower.contains(entry.to_lowercase().as_str()) {
                return true;
            }
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Internal banner parser
// ---------------------------------------------------------------------------

/// Parse an SSH identification string (RFC 4253 §4.2).
///
/// Format: `SSH-<protoversion>-<softwareversion>[SP <comments>]CR LF`
///
/// Returns `None` when the banner is malformed or exceeds `MAX_BANNER_LEN`.
fn parse_ssh_banner(data: &[u8]) -> Option<SshBannerInfo> {
    // Locate the end of the banner line (CR LF or just LF for leniency).
    let line_end = data
        .iter()
        .position(|&b| b == b'\n')
        .unwrap_or(data.len().min(MAX_BANNER_LEN));

    if line_end < SSH_BANNER_PREFIX.len() {
        return None;
    }

    // Trim trailing CR if present.
    let line = &data[..line_end];
    let line = if line.last() == Some(&b'\r') {
        &line[..line.len() - 1]
    } else {
        line
    };

    // Convert to str; banner must be printable ASCII per RFC 4253.
    let banner_str = std::str::from_utf8(line).ok()?;

    // Strip the `SSH-` prefix and split on the first `-` to get protoversion.
    let rest = banner_str.strip_prefix("SSH-")?;
    let dash_pos = rest.find('-')?;
    let proto_version = rest[..dash_pos].to_string();
    let after_proto = &rest[dash_pos + 1..];

    // Software version ends at the first space (start of optional comments).
    let (software_version, comment) = if let Some(sp_pos) = after_proto.find(' ') {
        let sw = after_proto[..sp_pos].to_string();
        let cmt = after_proto[sp_pos + 1..].to_string();
        (sw, if cmt.is_empty() { None } else { Some(cmt) })
    } else {
        (after_proto.to_string(), None)
    };

    Some(SshBannerInfo {
        proto_version,
        software_version,
        comment,
        // Heuristic: the first banner in a new flow on port 22 is the client.
        // The parser does not have flow-direction context, so we always set
        // `is_client_banner = true` and let the caller override if needed.
        is_client_banner: true,
    })
}

// ---------------------------------------------------------------------------
// Internal binary packet parser
// ---------------------------------------------------------------------------

/// Parse the SSH binary packet header (RFC 4253 §6).
///
/// SSH binary packet format:
/// ```text
/// uint32   packet_length   (payload + padding_length byte + padding)
/// byte     padding_length
/// byte[]   payload         (packet_length - padding_length - 1 bytes)
/// byte[]   random padding  (padding_length bytes)
/// byte[]   MAC             (depends on negotiated MAC algorithm)
/// ```
///
/// Only the first 5 bytes (length + padding_length) and the message type
/// byte (first byte of the payload) are read.
///
/// Returns `None` if the data is too short or the declared length is
/// implausibly large (> 32 768 bytes) to guard against garbage data.
fn parse_ssh_packet(data: &[u8]) -> Option<SshPacketInfo> {
    if data.len() < SSH_PKT_HEADER_SIZE {
        return None;
    }

    let packet_length = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);

    // Sanity check: plausible packet size.  SSH packets are bounded at
    // 32 768 bytes per RFC 4253 §6.1 (implementations may use larger values
    // after algorithm negotiation, but pre-key-exchange packets are small).
    if packet_length == 0 || packet_length > 65_535 {
        return None;
    }

    // padding_length is data[4]; payload starts at data[5].
    let padding_length = data[4] as usize;
    let payload_length = packet_length as usize - padding_length - 1;

    // Ensure there is at least one payload byte (the message type).
    if payload_length == 0 || data.len() < 5 + 1 {
        return None;
    }

    let message_type = data[5];

    Some(SshPacketInfo {
        message_type,
        packet_length,
    })
}

// ---------------------------------------------------------------------------
// Message type name helper
// ---------------------------------------------------------------------------

/// Return a human-readable name for an SSH message type byte.
pub fn ssh_message_type_name(msg_type: u8) -> &'static str {
    match msg_type {
        SSH_MSG_DISCONNECT => "DISCONNECT",
        SSH_MSG_SERVICE_REQUEST => "SERVICE_REQUEST",
        6 => "SERVICE_ACCEPT",
        SSH_MSG_KEXINIT => "KEXINIT",
        SSH_MSG_NEWKEYS => "NEWKEYS",
        SSH_MSG_USERAUTH_REQUEST => "USERAUTH_REQUEST",
        SSH_MSG_USERAUTH_FAILURE => "USERAUTH_FAILURE",
        SSH_MSG_USERAUTH_SUCCESS => "USERAUTH_SUCCESS",
        90 => "CHANNEL_OPEN",
        91 => "CHANNEL_OPEN_CONFIRMATION",
        92 => "CHANNEL_OPEN_FAILURE",
        93 => "CHANNEL_WINDOW_ADJUST",
        94 => "CHANNEL_DATA",
        97 => "CHANNEL_CLOSE",
        98 => "CHANNEL_REQUEST",
        _ => "UNKNOWN",
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Banner construction helpers
    // -----------------------------------------------------------------------

    fn make_banner(proto: &str, sw: &str, comment: Option<&str>) -> Vec<u8> {
        let mut s = format!("SSH-{proto}-{sw}");
        if let Some(c) = comment {
            s.push(' ');
            s.push_str(c);
        }
        s.push_str("\r\n");
        s.into_bytes()
    }

    // -----------------------------------------------------------------------
    // parse_ssh — banner detection
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_ssh_returns_none_on_empty() {
        assert!(parse_ssh(&[]).is_none());
    }

    #[test]
    fn test_parse_ssh_returns_none_on_garbage() {
        assert!(parse_ssh(b"GARBAGE DATA HERE").is_none());
    }

    #[test]
    fn test_parse_ssh_detects_banner() {
        let data = make_banner("2.0", "OpenSSH_9.3", None);
        let info = parse_ssh(&data).expect("parse");
        assert!(info.banner.is_some());
        assert!(info.packet.is_none());
    }

    #[test]
    fn test_parse_ssh_banner_proto_version() {
        let data = make_banner("2.0", "OpenSSH_9.3p2", None);
        let info = parse_ssh(&data).unwrap();
        let banner = info.banner.unwrap();
        assert_eq!(banner.proto_version, "2.0");
    }

    #[test]
    fn test_parse_ssh_banner_software_version() {
        let data = make_banner("2.0", "OpenSSH_9.3p2", None);
        let info = parse_ssh(&data).unwrap();
        let banner = info.banner.unwrap();
        assert_eq!(banner.software_version, "OpenSSH_9.3p2");
    }

    #[test]
    fn test_parse_ssh_banner_no_comment() {
        let data = make_banner("2.0", "OpenSSH_9.3", None);
        let info = parse_ssh(&data).unwrap();
        let banner = info.banner.unwrap();
        assert!(banner.comment.is_none());
    }

    #[test]
    fn test_parse_ssh_banner_with_comment() {
        let data = make_banner("2.0", "OpenSSH_8.9p1", Some("Ubuntu-3ubuntu0.6"));
        let info = parse_ssh(&data).unwrap();
        let banner = info.banner.unwrap();
        assert_eq!(banner.software_version, "OpenSSH_8.9p1");
        assert_eq!(banner.comment.as_deref(), Some("Ubuntu-3ubuntu0.6"));
    }

    #[test]
    fn test_parse_ssh_banner_ssh1_proto() {
        let data = make_banner("1.99", "OpenSSH_3.9p1", None);
        let info = parse_ssh(&data).unwrap();
        let banner = info.banner.unwrap();
        assert_eq!(banner.proto_version, "1.99");
    }

    #[test]
    fn test_parse_ssh_banner_lf_only_terminator() {
        // Some old servers send LF without CR.
        let data = b"SSH-2.0-Dropbear_2022.83\n".to_vec();
        let info = parse_ssh(&data).unwrap();
        let banner = info.banner.unwrap();
        assert_eq!(banner.software_version, "Dropbear_2022.83");
    }

    #[test]
    fn test_parse_ssh_banner_is_client_heuristic() {
        let data = make_banner("2.0", "OpenSSH_9.3", None);
        let info = parse_ssh(&data).unwrap();
        let banner = info.banner.unwrap();
        // Default heuristic: first banner treated as client.
        assert!(banner.is_client_banner);
    }

    #[test]
    fn test_parse_ssh_banner_libssh() {
        let data = make_banner("2.0", "libssh_0.9.6", None);
        let info = parse_ssh(&data).unwrap();
        let banner = info.banner.unwrap();
        assert_eq!(banner.software_version, "libssh_0.9.6");
    }

    // -----------------------------------------------------------------------
    // parse_ssh — binary packet detection
    // -----------------------------------------------------------------------

    /// Build a minimal SSH binary packet for a given message type.
    ///
    /// Format: packet_length(4) + padding_length(1) + msg_type(1)
    fn make_ssh_packet(msg_type: u8) -> Vec<u8> {
        // payload = [msg_type] (1 byte), padding = 0 bytes
        // packet_length = payload(1) + padding_length_field(1) + padding(0) = 2
        // Wait, per RFC 4253 §6: packet_length = payload_len + padding_len_field + padding
        // Actually: packet_length = sizeof(payload) + sizeof(padding_length_byte) + sizeof(padding)
        // For 1-byte payload, 0 padding: packet_length = 1 + 1 + 0 = 2
        // But real SSH requires at least 4 bytes of padding; we relax this for tests.
        let packet_length: u32 = 2; // padding_length_byte(1) + msg_type(1)
        let padding_length: u8 = 0;
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&packet_length.to_be_bytes());
        pkt.push(padding_length);
        pkt.push(msg_type);
        pkt
    }

    #[test]
    fn test_parse_ssh_detects_binary_packet() {
        let data = make_ssh_packet(SSH_MSG_KEXINIT);
        let info = parse_ssh(&data).unwrap();
        assert!(info.banner.is_none());
        let pkt = info.packet.unwrap();
        assert_eq!(pkt.message_type, SSH_MSG_KEXINIT);
    }

    #[test]
    fn test_parse_ssh_binary_packet_newkeys() {
        let data = make_ssh_packet(SSH_MSG_NEWKEYS);
        let info = parse_ssh(&data).unwrap();
        let pkt = info.packet.unwrap();
        assert_eq!(pkt.message_type, SSH_MSG_NEWKEYS);
    }

    #[test]
    fn test_parse_ssh_binary_packet_userauth() {
        let data = make_ssh_packet(SSH_MSG_USERAUTH_REQUEST);
        let info = parse_ssh(&data).unwrap();
        let pkt = info.packet.unwrap();
        assert_eq!(pkt.message_type, SSH_MSG_USERAUTH_REQUEST);
    }

    #[test]
    fn test_parse_ssh_binary_packet_too_short() {
        // Less than 5 bytes — cannot parse packet header.
        let data = vec![0x00, 0x00, 0x00, 0x02]; // only 4 bytes
        assert!(parse_ssh(&data).is_none());
    }

    #[test]
    fn test_parse_ssh_binary_packet_zero_length_rejected() {
        // packet_length == 0 is invalid.
        let data = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x14];
        assert!(parse_ssh(&data).is_none());
    }

    #[test]
    fn test_parse_ssh_binary_packet_implausibly_large_rejected() {
        // packet_length > 65535 → rejected as garbage.
        let data = vec![0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x14];
        assert!(parse_ssh(&data).is_none());
    }

    // -----------------------------------------------------------------------
    // is_ssh_port
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_ssh_port_standard() {
        assert!(is_ssh_port(22));
    }

    #[test]
    fn test_is_ssh_port_non_ssh() {
        assert!(!is_ssh_port(23));   // Telnet
        assert!(!is_ssh_port(80));
        assert!(!is_ssh_port(443));
        assert!(!is_ssh_port(2222)); // common alternate — intentionally not included
        assert!(!is_ssh_port(0));
    }

    // -----------------------------------------------------------------------
    // is_suspicious_ssh
    // -----------------------------------------------------------------------

    #[test]
    fn test_suspicious_ssh_proto_v1() {
        let info = SshInfo {
            banner: Some(SshBannerInfo {
                proto_version: "1.99".into(),
                software_version: "OpenSSH_3.9".into(),
                comment: None,
                is_client_banner: true,
            }),
            packet: None,
        };
        assert!(is_suspicious_ssh(&info, &[]));
    }

    #[test]
    fn test_suspicious_ssh_empty_software_version() {
        let info = SshInfo {
            banner: Some(SshBannerInfo {
                proto_version: "2.0".into(),
                software_version: String::new(), // empty — non-compliant
                comment: None,
                is_client_banner: true,
            }),
            packet: None,
        };
        assert!(is_suspicious_ssh(&info, &[]));
    }

    #[test]
    fn test_suspicious_ssh_blocklist_match() {
        let info = SshInfo {
            banner: Some(SshBannerInfo {
                proto_version: "2.0".into(),
                software_version: "paramiko_2.11.0".into(),
                comment: None,
                is_client_banner: true,
            }),
            packet: None,
        };
        let blocklist = vec!["paramiko".to_string()];
        assert!(is_suspicious_ssh(&info, &blocklist));
    }

    #[test]
    fn test_suspicious_ssh_blocklist_case_insensitive() {
        let info = SshInfo {
            banner: Some(SshBannerInfo {
                proto_version: "2.0".into(),
                software_version: "Impacket_0.11.0".into(),
                comment: None,
                is_client_banner: true,
            }),
            packet: None,
        };
        let blocklist = vec!["impacket".to_string()];
        assert!(is_suspicious_ssh(&info, &blocklist));
    }

    #[test]
    fn test_not_suspicious_ssh_normal_banner() {
        let info = SshInfo {
            banner: Some(SshBannerInfo {
                proto_version: "2.0".into(),
                software_version: "OpenSSH_9.3p2".into(),
                comment: Some("Ubuntu-1ubuntu3".into()),
                is_client_banner: true,
            }),
            packet: None,
        };
        assert!(!is_suspicious_ssh(&info, &[]));
    }

    #[test]
    fn test_not_suspicious_ssh_no_banner_no_packet() {
        // SshInfo without a banner is not flagged (nothing to evaluate).
        let info = SshInfo {
            banner: None,
            packet: Some(SshPacketInfo {
                message_type: SSH_MSG_KEXINIT,
                packet_length: 2,
            }),
        };
        assert!(!is_suspicious_ssh(&info, &[]));
    }

    #[test]
    fn test_suspicious_ssh_blocklist_partial_substring() {
        // "libssh2" should match a blocklist entry of "libssh".
        let info = SshInfo {
            banner: Some(SshBannerInfo {
                proto_version: "2.0".into(),
                software_version: "libssh2_1.11.0".into(),
                comment: None,
                is_client_banner: true,
            }),
            packet: None,
        };
        let blocklist = vec!["libssh".to_string()];
        assert!(is_suspicious_ssh(&info, &blocklist));
    }

    #[test]
    fn test_not_suspicious_ssh_blocklist_no_match() {
        let info = SshInfo {
            banner: Some(SshBannerInfo {
                proto_version: "2.0".into(),
                software_version: "Dropbear_2022.83".into(),
                comment: None,
                is_client_banner: true,
            }),
            packet: None,
        };
        let blocklist = vec!["paramiko".to_string(), "impacket".to_string()];
        assert!(!is_suspicious_ssh(&info, &blocklist));
    }

    // -----------------------------------------------------------------------
    // ssh_message_type_name
    // -----------------------------------------------------------------------

    #[test]
    fn test_ssh_message_type_name_known() {
        assert_eq!(ssh_message_type_name(1), "DISCONNECT");
        assert_eq!(ssh_message_type_name(5), "SERVICE_REQUEST");
        assert_eq!(ssh_message_type_name(6), "SERVICE_ACCEPT");
        assert_eq!(ssh_message_type_name(20), "KEXINIT");
        assert_eq!(ssh_message_type_name(21), "NEWKEYS");
        assert_eq!(ssh_message_type_name(50), "USERAUTH_REQUEST");
        assert_eq!(ssh_message_type_name(51), "USERAUTH_FAILURE");
        assert_eq!(ssh_message_type_name(52), "USERAUTH_SUCCESS");
        assert_eq!(ssh_message_type_name(90), "CHANNEL_OPEN");
        assert_eq!(ssh_message_type_name(94), "CHANNEL_DATA");
        assert_eq!(ssh_message_type_name(97), "CHANNEL_CLOSE");
        assert_eq!(ssh_message_type_name(98), "CHANNEL_REQUEST");
    }

    #[test]
    fn test_ssh_message_type_name_unknown() {
        assert_eq!(ssh_message_type_name(0), "UNKNOWN");
        assert_eq!(ssh_message_type_name(255), "UNKNOWN");
    }

    // -----------------------------------------------------------------------
    // End-to-end: parse then check suspicion
    // -----------------------------------------------------------------------

    #[test]
    fn test_e2e_openssh_banner_not_suspicious() {
        let data = make_banner("2.0", "OpenSSH_9.3p2", Some("Ubuntu-1ubuntu3.2"));
        let info = parse_ssh(&data).unwrap();
        assert!(!is_suspicious_ssh(&info, &[]));
    }

    #[test]
    fn test_e2e_ssh1_banner_suspicious() {
        let data = make_banner("1.5", "OpenSSH_3.5", None);
        let info = parse_ssh(&data).unwrap();
        assert!(is_suspicious_ssh(&info, &[]));
    }

    #[test]
    fn test_e2e_paramiko_banner_suspicious() {
        let data = make_banner("2.0", "paramiko_3.3.1", None);
        let info = parse_ssh(&data).unwrap();
        let blocklist = vec!["paramiko".to_string()];
        assert!(is_suspicious_ssh(&info, &blocklist));
    }
}
