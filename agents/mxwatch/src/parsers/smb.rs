//! SMB2/CIFS protocol parser — feature 25.8.
//!
//! Parses SMB2 frames from TCP payloads on port 445 to provide visibility
//! into file-sharing activity, lateral movement, and ransomware indicators.
//!
//! # Capabilities
//! - Detects SMB2 magic (`\xFESMB`) and SMB1 legacy magic (`\xFFSMB`).
//! - Parses the 64-byte SMB2 fixed header (MS-SMB2 §2.2.1.2): command,
//!   flags, NT status, session ID, and tree ID.
//! - Provides SMB2 command name lookup for all 18 standard commands.
//! - Detects suspicious patterns: SMB1 usage (EternalBlue vector), null
//!   (anonymous) sessions, and unsigned sessions performing write operations.
//!
//! # Limitations
//! - SMB1 parsing is limited to magic detection only; the SMB1 header format
//!   differs significantly and the protocol is deprecated (RFC 7143).
//! - Encrypted SMB3 sessions cannot be parsed past the NEGOTIATE phase.
//! - Multi-credit compound requests are treated as a single command (the
//!   first request in the compound chain).
//! - NetBIOS Session Service over port 139 is out of scope; only port 445
//!   (SMB-over-TCP, also called "Direct Hosting") is supported.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// SMB protocol constants
// ---------------------------------------------------------------------------

/// SMB2 protocol magic bytes: 0xFE + "SMB" (MS-SMB2 §2.2.1.2).
pub const SMB2_MAGIC: [u8; 4] = [0xFE, 0x53, 0x4D, 0x42];

/// SMB1/CIFS legacy protocol magic bytes: 0xFF + "SMB".
pub const SMB1_MAGIC: [u8; 4] = [0xFF, 0x53, 0x4D, 0x42];

/// NBT Session Service message type (type field = 0x00, RFC 1002 §4.3.1).
pub const NBT_SESSION_MESSAGE: u8 = 0x00;

/// Size of the NetBIOS Session Service (NBT) header prefix in bytes.
pub const NBT_HEADER_SIZE: usize = 4;

/// Minimum size of a complete SMB2 fixed header in bytes.
pub const SMB2_HEADER_SIZE: usize = 64;

// SMB2 command codes (MS-SMB2 §2.2.1.2 — Command field).
pub const SMB2_NEGOTIATE: u16 = 0x0000;
pub const SMB2_SESSION_SETUP: u16 = 0x0001;
pub const SMB2_LOGOFF: u16 = 0x0002;
pub const SMB2_TREE_CONNECT: u16 = 0x0003;
pub const SMB2_TREE_DISCONNECT: u16 = 0x0004;
pub const SMB2_CREATE: u16 = 0x0005;
pub const SMB2_CLOSE: u16 = 0x0006;
pub const SMB2_FLUSH: u16 = 0x0007;
pub const SMB2_READ: u16 = 0x0008;
pub const SMB2_WRITE: u16 = 0x0009;
pub const SMB2_LOCK: u16 = 0x000A;
pub const SMB2_IOCTL: u16 = 0x000B;
pub const SMB2_CANCEL: u16 = 0x000C;
pub const SMB2_ECHO: u16 = 0x000D;
pub const SMB2_QUERY_DIRECTORY: u16 = 0x000E;
pub const SMB2_CHANGE_NOTIFY: u16 = 0x000F;
pub const SMB2_QUERY_INFO: u16 = 0x0010;
pub const SMB2_SET_INFO: u16 = 0x0011;
pub const SMB2_OPLOCK_BREAK: u16 = 0x0012;

// SMB2 Flags field bits (MS-SMB2 §2.2.1.2).

/// Flags: packet is a server-to-client response.
pub const SMB2_FLAGS_RESPONSE: u32 = 0x0000_0001;
/// Flags: all messages in the compound chain are related.
pub const SMB2_FLAGS_RELATED: u32 = 0x0000_0004;
/// Flags: packet is cryptographically signed (HMAC-SHA-256 / AES-CMAC).
pub const SMB2_FLAGS_SIGNED: u32 = 0x0000_0008;

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// SMB protocol version detected from the magic bytes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SmbVersion {
    /// SMB2/3 — the modern dialect (Windows Vista+, Samba 3.6+).
    Smb2,
    /// Legacy SMB1/CIFS — deprecated, EternalBlue-vulnerable (CVE-2017-0144).
    Smb1,
}

/// Parsed metadata extracted from an SMB2 header or an SMB1 magic detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmbInfo {
    /// Protocol version identified from the magic bytes.
    pub version: SmbVersion,

    /// SMB2 command code (absent for SMB1 — only version is extracted).
    pub command: Option<u16>,

    /// Human-readable SMB2 command name (e.g., `"CREATE"`, `"SESSION_SETUP"`).
    pub command_name: Option<String>,

    /// NT status / error code from server responses (little-endian u32).
    ///
    /// Common values: 0x00000000 (STATUS_SUCCESS),
    /// 0xC000006D (STATUS_LOGON_FAILURE), 0xC0000022 (STATUS_ACCESS_DENIED).
    pub status: Option<u32>,

    /// Session identifier established during SESSION_SETUP (little-endian u64).
    ///
    /// A value of `0` indicates an unauthenticated (null/anonymous) session.
    pub session_id: Option<u64>,

    /// Tree identifier representing the connected share (little-endian u32).
    ///
    /// Established by TREE_CONNECT; reset to 0 after TREE_DISCONNECT.
    pub tree_id: Option<u32>,

    /// True when the RESPONSE flag (0x00000001) is set — packet from server.
    pub is_response: bool,

    /// True when the SIGNED flag (0x00000008) is **not** set.
    ///
    /// Unsigned SMB2 sessions are vulnerable to NTLM-relay attacks (e.g.,
    /// Responder + ntlmrelayx).  Write-class commands over unsigned sessions
    /// are a common lateral-movement technique.
    pub unsigned: bool,
}

// ---------------------------------------------------------------------------
// Public parsing API
// ---------------------------------------------------------------------------

/// Attempt to parse an SMB2 header (or detect SMB1) from a raw TCP payload.
///
/// The payload may be prefixed by a 4-byte NBT Session Service header
/// (byte[0] == 0x00 = Session Message); both wrapped and bare SMB2 headers
/// are handled transparently.
///
/// Returns `None` when the payload does not contain a recognisable SMB magic.
/// Returns `Some(SmbInfo)` with partial fields when the payload is long enough
/// to detect the magic but too short to decode the full 64-byte header.
pub fn parse_smb(data: &[u8]) -> Option<SmbInfo> {
    if data.len() < 4 {
        return None;
    }

    // Determine where the SMB header starts.
    // If byte[0] == 0x00 (NBT Session Message) and there is room for an NBT
    // header plus at least 4 magic bytes, skip the 4-byte NBT prefix.
    // Otherwise assume the payload begins directly with the SMB magic.
    let smb_offset = if data[0] == NBT_SESSION_MESSAGE && data.len() >= NBT_HEADER_SIZE + 4 {
        NBT_HEADER_SIZE
    } else {
        0
    };

    let smb_data = &data[smb_offset..];
    if smb_data.len() < 4 {
        return None;
    }

    // --- SMB1 detection -------------------------------------------------------
    // SMB1 is flagged immediately; no further field parsing is attempted
    // because the SMB1 header layout differs from SMB2 and the dialect is
    // deprecated across all modern deployments.
    if smb_data.starts_with(&SMB1_MAGIC) {
        return Some(SmbInfo {
            version: SmbVersion::Smb1,
            command: None,
            command_name: None,
            status: None,
            session_id: None,
            tree_id: None,
            is_response: false,
            unsigned: true, // SMB1 lacks mandatory signing enforcement
        });
    }

    // --- SMB2 header detection -------------------------------------------------
    if !smb_data.starts_with(&SMB2_MAGIC) {
        return None;
    }

    // Partial header: magic confirmed but fewer than 64 bytes available.
    if smb_data.len() < SMB2_HEADER_SIZE {
        return Some(SmbInfo {
            version: SmbVersion::Smb2,
            command: None,
            command_name: None,
            status: None,
            session_id: None,
            tree_id: None,
            is_response: false,
            unsigned: false,
        });
    }

    // --- SMB2 fixed-header field extraction -----------------------------------
    //
    // SMB2 header layout (MS-SMB2 §2.2.1.2, all fields little-endian):
    //   Offset  Size  Field
    //    0       4    ProtocolId      (0xFE534D42)
    //    4       2    StructureSize   (always 64)
    //    6       2    CreditCharge
    //    8       4    Status          (NT status code)
    //   12       2    Command
    //   14       2    CreditRequest / CreditResponse
    //   16       4    Flags
    //   20       4    NextCommand
    //   24       8    MessageId
    //   32       4    ProcessId (reserved in async mode)
    //   36       4    TreeId
    //   40       8    SessionId
    //   48      16    Signature
    let status = u32::from_le_bytes([smb_data[8], smb_data[9], smb_data[10], smb_data[11]]);
    let command = u16::from_le_bytes([smb_data[12], smb_data[13]]);
    let flags = u32::from_le_bytes([smb_data[16], smb_data[17], smb_data[18], smb_data[19]]);
    let tree_id = u32::from_le_bytes([smb_data[36], smb_data[37], smb_data[38], smb_data[39]]);
    let session_id = u64::from_le_bytes([
        smb_data[40], smb_data[41], smb_data[42], smb_data[43],
        smb_data[44], smb_data[45], smb_data[46], smb_data[47],
    ]);

    let is_response = (flags & SMB2_FLAGS_RESPONSE) != 0;
    let unsigned = (flags & SMB2_FLAGS_SIGNED) == 0;

    Some(SmbInfo {
        version: SmbVersion::Smb2,
        command: Some(command),
        command_name: Some(smb2_command_name(command).to_string()),
        status: Some(status),
        session_id: Some(session_id),
        tree_id: Some(tree_id),
        is_response,
        unsigned,
    })
}

// ---------------------------------------------------------------------------
// Port and name helpers
// ---------------------------------------------------------------------------

/// Return `true` if `port` is the standard SMB-over-TCP port (445).
///
/// Port 139 (legacy NetBIOS Session Service) is intentionally excluded; modern
/// deployments use port 445 exclusively and perimeter firewalls typically
/// block port 139.
pub fn is_smb_port(port: u16) -> bool {
    port == 445
}

/// Return a human-readable name for an SMB2 command code.
///
/// Returns `"UNKNOWN"` for command codes not defined in MS-SMB2 §2.2.
pub fn smb2_command_name(command: u16) -> &'static str {
    match command {
        SMB2_NEGOTIATE => "NEGOTIATE",
        SMB2_SESSION_SETUP => "SESSION_SETUP",
        SMB2_LOGOFF => "LOGOFF",
        SMB2_TREE_CONNECT => "TREE_CONNECT",
        SMB2_TREE_DISCONNECT => "TREE_DISCONNECT",
        SMB2_CREATE => "CREATE",
        SMB2_CLOSE => "CLOSE",
        SMB2_FLUSH => "FLUSH",
        SMB2_READ => "READ",
        SMB2_WRITE => "WRITE",
        SMB2_LOCK => "LOCK",
        SMB2_IOCTL => "IOCTL",
        SMB2_CANCEL => "CANCEL",
        SMB2_ECHO => "ECHO",
        SMB2_QUERY_DIRECTORY => "QUERY_DIRECTORY",
        SMB2_CHANGE_NOTIFY => "CHANGE_NOTIFY",
        SMB2_QUERY_INFO => "QUERY_INFO",
        SMB2_SET_INFO => "SET_INFO",
        SMB2_OPLOCK_BREAK => "OPLOCK_BREAK",
        _ => "UNKNOWN",
    }
}

// ---------------------------------------------------------------------------
// Suspicion detection
// ---------------------------------------------------------------------------

/// Return `true` if the SMB session exhibits suspicious security indicators.
///
/// Detection categories:
///
/// - **SMB1 usage**: The legacy dialect is deprecated and affected by
///   EternalBlue (CVE-2017-0144), WannaCry, and NotPetya.  Any SMB1
///   traffic is considered suspicious in post-2017 environments.
///
/// - **Null (anonymous) session**: A `session_id` of 0 after NEGOTIATE
///   indicates an unauthenticated session, often used for share enumeration
///   (e.g., `net view`, CrackMapExec `--shares`).
///
/// - **Unsigned session + write-class command**: SMB signing disabled while
///   performing CREATE, WRITE, IOCTL, or SET_INFO is the attack surface for
///   NTLM-relay (Responder, ntlmrelayx, PetitPotam).
pub fn is_suspicious_smb(info: &SmbInfo) -> bool {
    // SMB1 is deprecated and historically exploitable.
    if info.version == SmbVersion::Smb1 {
        return true;
    }

    // Null/anonymous session attempting anything beyond NEGOTIATE.
    if info.session_id == Some(0) && info.command != Some(SMB2_NEGOTIATE) {
        return true;
    }

    // Unsigned session performing a write-class or privileged operation.
    if info.unsigned {
        if let Some(cmd) = info.command {
            if matches!(cmd, SMB2_CREATE | SMB2_WRITE | SMB2_IOCTL | SMB2_SET_INFO) {
                return true;
            }
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Packet construction helpers
    // -----------------------------------------------------------------------

    /// Build a minimal 4-byte NBT header prefix.
    ///
    /// Format: type(1) + length(3 bytes big-endian).
    fn nbt_header(payload_len: usize) -> [u8; 4] {
        [
            NBT_SESSION_MESSAGE,
            ((payload_len >> 16) & 0xFF) as u8,
            ((payload_len >> 8) & 0xFF) as u8,
            (payload_len & 0xFF) as u8,
        ]
    }

    /// Build a complete 64-byte SMB2 fixed header with the given fields.
    ///
    /// All unspecified bytes are zero.  Fields follow MS-SMB2 §2.2.1.2
    /// (little-endian layout).
    fn build_smb2_header(
        command: u16,
        flags: u32,
        status: u32,
        session_id: u64,
        tree_id: u32,
    ) -> Vec<u8> {
        let mut hdr = vec![0u8; SMB2_HEADER_SIZE];
        // ProtocolId
        hdr[0..4].copy_from_slice(&SMB2_MAGIC);
        // StructureSize = 64
        hdr[4..6].copy_from_slice(&64u16.to_le_bytes());
        // Status
        hdr[8..12].copy_from_slice(&status.to_le_bytes());
        // Command
        hdr[12..14].copy_from_slice(&command.to_le_bytes());
        // Flags
        hdr[16..20].copy_from_slice(&flags.to_le_bytes());
        // TreeId
        hdr[36..40].copy_from_slice(&tree_id.to_le_bytes());
        // SessionId
        hdr[40..48].copy_from_slice(&session_id.to_le_bytes());
        hdr
    }

    /// Build an NBT-wrapped SMB2 packet.
    fn build_nbt_smb2(command: u16, flags: u32, status: u32, session_id: u64, tree_id: u32) -> Vec<u8> {
        let smb_hdr = build_smb2_header(command, flags, status, session_id, tree_id);
        let nbt = nbt_header(smb_hdr.len());
        let mut pkt = Vec::with_capacity(nbt.len() + smb_hdr.len());
        pkt.extend_from_slice(&nbt);
        pkt.extend_from_slice(&smb_hdr);
        pkt
    }

    // -----------------------------------------------------------------------
    // parse_smb — basic validation
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_smb_too_short_returns_none() {
        assert!(parse_smb(&[]).is_none());
        assert!(parse_smb(&[0x00, 0x00, 0x00]).is_none());
    }

    #[test]
    fn test_parse_smb_garbage_returns_none() {
        assert!(parse_smb(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE]).is_none());
    }

    #[test]
    fn test_parse_smb_bare_smb2_header() {
        // SMB2 header without NBT wrapper.
        let pkt = build_smb2_header(SMB2_NEGOTIATE, 0, 0, 0, 0);
        let info = parse_smb(&pkt).expect("parse");
        assert_eq!(info.version, SmbVersion::Smb2);
        assert_eq!(info.command, Some(SMB2_NEGOTIATE));
        assert_eq!(info.command_name.as_deref(), Some("NEGOTIATE"));
    }

    #[test]
    fn test_parse_smb_nbt_wrapped_smb2() {
        let pkt = build_nbt_smb2(SMB2_SESSION_SETUP, 0, 0, 0x1234_5678_9ABC_DEF0, 0);
        let info = parse_smb(&pkt).expect("parse");
        assert_eq!(info.version, SmbVersion::Smb2);
        assert_eq!(info.command, Some(SMB2_SESSION_SETUP));
        assert_eq!(info.session_id, Some(0x1234_5678_9ABC_DEF0));
    }

    #[test]
    fn test_parse_smb_smb1_magic_detected() {
        let mut pkt = vec![0u8; 8];
        pkt[0..4].copy_from_slice(&SMB1_MAGIC);
        let info = parse_smb(&pkt).expect("parse");
        assert_eq!(info.version, SmbVersion::Smb1);
        assert!(info.command.is_none());
        assert!(info.unsigned); // SMB1 is flagged as unsigned
    }

    #[test]
    fn test_parse_smb_smb1_with_nbt_wrapper() {
        let smb1 = SMB1_MAGIC.to_vec();
        let nbt = nbt_header(smb1.len());
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&nbt);
        pkt.extend_from_slice(&smb1);
        let info = parse_smb(&pkt).expect("parse");
        assert_eq!(info.version, SmbVersion::Smb1);
    }

    // -----------------------------------------------------------------------
    // parse_smb — field extraction
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_smb_status_field() {
        // STATUS_LOGON_FAILURE = 0xC000006D
        let status = 0xC000_006D_u32;
        let flags = SMB2_FLAGS_RESPONSE; // response packet
        let pkt = build_nbt_smb2(SMB2_SESSION_SETUP, flags, status, 0, 0);
        let info = parse_smb(&pkt).expect("parse");
        assert_eq!(info.status, Some(0xC000_006D));
        assert!(info.is_response);
    }

    #[test]
    fn test_parse_smb_tree_id_field() {
        let pkt = build_nbt_smb2(SMB2_TREE_CONNECT, 0, 0, 0xABCDu64, 0x0007_0001);
        let info = parse_smb(&pkt).expect("parse");
        assert_eq!(info.tree_id, Some(0x0007_0001));
        assert_eq!(info.session_id, Some(0xABCD));
    }

    #[test]
    fn test_parse_smb_is_response_flag() {
        let flags_req = 0u32;
        let flags_resp = SMB2_FLAGS_RESPONSE;
        let pkt_req = build_nbt_smb2(SMB2_READ, flags_req, 0, 0x1, 0x1);
        let pkt_resp = build_nbt_smb2(SMB2_READ, flags_resp, 0, 0x1, 0x1);
        assert!(!parse_smb(&pkt_req).unwrap().is_response);
        assert!(parse_smb(&pkt_resp).unwrap().is_response);
    }

    #[test]
    fn test_parse_smb_signed_session_not_flagged_unsigned() {
        let flags = SMB2_FLAGS_SIGNED; // signing enabled
        let pkt = build_nbt_smb2(SMB2_CREATE, flags, 0, 0x1, 0x1);
        let info = parse_smb(&pkt).expect("parse");
        assert!(!info.unsigned);
    }

    #[test]
    fn test_parse_smb_unsigned_session_flagged() {
        let flags = 0u32; // signing NOT enabled
        let pkt = build_nbt_smb2(SMB2_WRITE, flags, 0, 0x1, 0x1);
        let info = parse_smb(&pkt).expect("parse");
        assert!(info.unsigned);
    }

    #[test]
    fn test_parse_smb_partial_header_returns_some() {
        // Fewer than 64 bytes after the NBT header → partial result.
        let short_smb2: Vec<u8> = SMB2_MAGIC.iter().cloned().chain(vec![0u8; 10]).collect();
        let nbt = nbt_header(short_smb2.len());
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&nbt);
        pkt.extend_from_slice(&short_smb2);
        let info = parse_smb(&pkt).expect("partial parse");
        assert_eq!(info.version, SmbVersion::Smb2);
        assert!(info.command.is_none()); // fields not available
    }

    // -----------------------------------------------------------------------
    // smb2_command_name
    // -----------------------------------------------------------------------

    #[test]
    fn test_smb2_command_name_all_known() {
        assert_eq!(smb2_command_name(SMB2_NEGOTIATE), "NEGOTIATE");
        assert_eq!(smb2_command_name(SMB2_SESSION_SETUP), "SESSION_SETUP");
        assert_eq!(smb2_command_name(SMB2_LOGOFF), "LOGOFF");
        assert_eq!(smb2_command_name(SMB2_TREE_CONNECT), "TREE_CONNECT");
        assert_eq!(smb2_command_name(SMB2_TREE_DISCONNECT), "TREE_DISCONNECT");
        assert_eq!(smb2_command_name(SMB2_CREATE), "CREATE");
        assert_eq!(smb2_command_name(SMB2_CLOSE), "CLOSE");
        assert_eq!(smb2_command_name(SMB2_FLUSH), "FLUSH");
        assert_eq!(smb2_command_name(SMB2_READ), "READ");
        assert_eq!(smb2_command_name(SMB2_WRITE), "WRITE");
        assert_eq!(smb2_command_name(SMB2_LOCK), "LOCK");
        assert_eq!(smb2_command_name(SMB2_IOCTL), "IOCTL");
        assert_eq!(smb2_command_name(SMB2_CANCEL), "CANCEL");
        assert_eq!(smb2_command_name(SMB2_ECHO), "ECHO");
        assert_eq!(smb2_command_name(SMB2_QUERY_DIRECTORY), "QUERY_DIRECTORY");
        assert_eq!(smb2_command_name(SMB2_CHANGE_NOTIFY), "CHANGE_NOTIFY");
        assert_eq!(smb2_command_name(SMB2_QUERY_INFO), "QUERY_INFO");
        assert_eq!(smb2_command_name(SMB2_SET_INFO), "SET_INFO");
        assert_eq!(smb2_command_name(SMB2_OPLOCK_BREAK), "OPLOCK_BREAK");
    }

    #[test]
    fn test_smb2_command_name_unknown() {
        assert_eq!(smb2_command_name(0xFFFF), "UNKNOWN");
        assert_eq!(smb2_command_name(0x0013), "UNKNOWN");
    }

    // -----------------------------------------------------------------------
    // is_smb_port
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_smb_port_standard() {
        assert!(is_smb_port(445));
    }

    #[test]
    fn test_is_smb_port_non_smb() {
        assert!(!is_smb_port(139)); // legacy NetBIOS — excluded by design
        assert!(!is_smb_port(80));
        assert!(!is_smb_port(443));
        assert!(!is_smb_port(22));
        assert!(!is_smb_port(0));
    }

    // -----------------------------------------------------------------------
    // is_suspicious_smb
    // -----------------------------------------------------------------------

    #[test]
    fn test_suspicious_smb1_always_flagged() {
        let info = SmbInfo {
            version: SmbVersion::Smb1,
            command: None,
            command_name: None,
            status: None,
            session_id: None,
            tree_id: None,
            is_response: false,
            unsigned: true,
        };
        assert!(is_suspicious_smb(&info));
    }

    #[test]
    fn test_suspicious_null_session_non_negotiate() {
        // session_id == 0 on a CREATE command → suspicious.
        let info = SmbInfo {
            version: SmbVersion::Smb2,
            command: Some(SMB2_CREATE),
            command_name: Some("CREATE".into()),
            status: Some(0),
            session_id: Some(0), // null session
            tree_id: Some(1),
            is_response: false,
            unsigned: false,
        };
        assert!(is_suspicious_smb(&info));
    }

    #[test]
    fn test_not_suspicious_null_session_on_negotiate() {
        // session_id == 0 is expected during NEGOTIATE (pre-auth).
        let info = SmbInfo {
            version: SmbVersion::Smb2,
            command: Some(SMB2_NEGOTIATE),
            command_name: Some("NEGOTIATE".into()),
            status: Some(0),
            session_id: Some(0),
            tree_id: Some(0),
            is_response: false,
            unsigned: false,
        };
        assert!(!is_suspicious_smb(&info));
    }

    #[test]
    fn test_suspicious_unsigned_write() {
        // Unsigned session + WRITE → NTLM-relay risk.
        let info = SmbInfo {
            version: SmbVersion::Smb2,
            command: Some(SMB2_WRITE),
            command_name: Some("WRITE".into()),
            status: Some(0),
            session_id: Some(0xBEEF),
            tree_id: Some(0xCAFE),
            is_response: false,
            unsigned: true,
        };
        assert!(is_suspicious_smb(&info));
    }

    #[test]
    fn test_suspicious_unsigned_create() {
        let info = SmbInfo {
            version: SmbVersion::Smb2,
            command: Some(SMB2_CREATE),
            command_name: Some("CREATE".into()),
            status: Some(0),
            session_id: Some(0x1),
            tree_id: Some(0x1),
            is_response: false,
            unsigned: true,
        };
        assert!(is_suspicious_smb(&info));
    }

    #[test]
    fn test_suspicious_unsigned_ioctl() {
        let info = SmbInfo {
            version: SmbVersion::Smb2,
            command: Some(SMB2_IOCTL),
            command_name: Some("IOCTL".into()),
            status: Some(0),
            session_id: Some(0x1),
            tree_id: Some(0x1),
            is_response: false,
            unsigned: true,
        };
        assert!(is_suspicious_smb(&info));
    }

    #[test]
    fn test_not_suspicious_unsigned_read() {
        // READ over unsigned channel is not flagged (read-only operations are
        // lower risk than writes).
        let info = SmbInfo {
            version: SmbVersion::Smb2,
            command: Some(SMB2_READ),
            command_name: Some("READ".into()),
            status: Some(0),
            session_id: Some(0x1),
            tree_id: Some(0x1),
            is_response: false,
            unsigned: true,
        };
        assert!(!is_suspicious_smb(&info));
    }

    #[test]
    fn test_not_suspicious_signed_write() {
        // Signed session + WRITE → not suspicious.
        let info = SmbInfo {
            version: SmbVersion::Smb2,
            command: Some(SMB2_WRITE),
            command_name: Some("WRITE".into()),
            status: Some(0),
            session_id: Some(0xBEEF),
            tree_id: Some(0xCAFE),
            is_response: false,
            unsigned: false, // signing enabled
        };
        assert!(!is_suspicious_smb(&info));
    }

    #[test]
    fn test_not_suspicious_normal_session() {
        let info = SmbInfo {
            version: SmbVersion::Smb2,
            command: Some(SMB2_QUERY_INFO),
            command_name: Some("QUERY_INFO".into()),
            status: Some(0),
            session_id: Some(0xDEAD_BEEF),
            tree_id: Some(0x1),
            is_response: false,
            unsigned: false,
        };
        assert!(!is_suspicious_smb(&info));
    }

    // -----------------------------------------------------------------------
    // End-to-end: parse then check suspicion
    // -----------------------------------------------------------------------

    #[test]
    fn test_e2e_smb2_signed_session_not_suspicious() {
        // Signed session doing a WRITE → clean.
        let flags = SMB2_FLAGS_SIGNED;
        let pkt = build_nbt_smb2(SMB2_WRITE, flags, 0, 0xABCD_1234, 0x2);
        let info = parse_smb(&pkt).expect("parse");
        assert!(!is_suspicious_smb(&info));
    }

    #[test]
    fn test_e2e_smb2_unsigned_create_suspicious() {
        // Unsigned CREATE → relay risk.
        let flags = 0u32;
        let pkt = build_nbt_smb2(SMB2_CREATE, flags, 0, 0x1, 0x1);
        let info = parse_smb(&pkt).expect("parse");
        assert!(is_suspicious_smb(&info));
    }

    #[test]
    fn test_e2e_smb1_detected_suspicious() {
        let smb1 = SMB1_MAGIC.to_vec();
        let nbt = nbt_header(smb1.len());
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&nbt);
        pkt.extend_from_slice(&smb1);
        let info = parse_smb(&pkt).expect("parse");
        assert!(is_suspicious_smb(&info));
    }
}
