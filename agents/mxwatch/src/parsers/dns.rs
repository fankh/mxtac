//! DNS wire-format parser — feature 25.5.
//!
//! Parses DNS queries **and** responses per RFC 1035 / RFC 3596 (AAAA).
//! All four message sections are parsed:
//!
//! - **Questions** — QNAME, QTYPE, QCLASS
//! - **Answers** — typed RDATA for A, AAAA, CNAME, NS, PTR, MX, TXT, SOA
//! - **Authority** — same typed RDATA
//! - **Additional** — same typed RDATA; EDNS0 OPT pseudo-records are skipped
//!
//! Unknown record types fall back to raw bytes so no data is silently dropped.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

// ---------------------------------------------------------------------------
// DNS record-type constants (TYPE / QTYPE — RFC 1035 and extensions)
// ---------------------------------------------------------------------------

pub const DNS_TYPE_A: u16 = 1;
pub const DNS_TYPE_NS: u16 = 2;
pub const DNS_TYPE_CNAME: u16 = 5;
pub const DNS_TYPE_SOA: u16 = 6;
pub const DNS_TYPE_PTR: u16 = 12;
pub const DNS_TYPE_MX: u16 = 15;
pub const DNS_TYPE_TXT: u16 = 16;
pub const DNS_TYPE_AAAA: u16 = 28;
pub const DNS_TYPE_SRV: u16 = 33;
/// EDNS0 OPT pseudo-record (RFC 6891).  Not a true resource record.
pub const DNS_TYPE_OPT: u16 = 41;
pub const DNS_TYPE_DS: u16 = 43;
pub const DNS_TYPE_RRSIG: u16 = 46;
pub const DNS_TYPE_NSEC: u16 = 47;
pub const DNS_TYPE_DNSKEY: u16 = 48;
/// QTYPE ANY — request all record types.
pub const DNS_TYPE_ANY: u16 = 255;

// DNS class constants
pub const DNS_CLASS_IN: u16 = 1;
pub const DNS_CLASS_ANY: u16 = 255;

// ---------------------------------------------------------------------------
// Safety limits (guard against malformed / adversarial packets)
// ---------------------------------------------------------------------------

/// Maximum questions to parse from one message.
const MAX_QUESTIONS: usize = 16;
/// Maximum resource records to parse per section.
const MAX_RECORDS: usize = 64;

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Parsed DNS message — covers both queries and responses.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DnsInfo {
    pub transaction_id: u16,
    pub is_response: bool,
    pub opcode: u8,
    pub rcode: u8,
    /// Raw flags word (for callers that need bits beyond QR / opcode / rcode).
    pub flags: u16,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub additionals: Vec<DnsRecord>,
}

/// One entry from the DNS question section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// A DNS resource record (answer, authority, or additional section).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: DnsRdata,
}

/// Parsed RDATA for well-known record types; raw bytes for anything else.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data")]
pub enum DnsRdata {
    /// IPv4 host address (A — RFC 1035).
    A(Ipv4Addr),
    /// IPv6 host address (AAAA — RFC 3596).
    Aaaa(Ipv6Addr),
    /// Canonical-name alias (CNAME — RFC 1035).
    Cname(String),
    /// Authoritative name server (NS — RFC 1035).
    Ns(String),
    /// Reverse-DNS pointer (PTR — RFC 1035).
    Ptr(String),
    /// Mail exchanger (MX — RFC 1035).
    Mx { preference: u16, exchange: String },
    /// One or more character strings (TXT — RFC 1035).
    Txt(Vec<String>),
    /// Start of authority (SOA — RFC 1035).
    Soa {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    /// Raw bytes for record types that are not specifically parsed.
    Unknown(Vec<u8>),
}

// ---------------------------------------------------------------------------
// Name / code lookup helpers
// ---------------------------------------------------------------------------

/// Return the canonical textual name for a DNS record type, e.g. `"A"`, `"MX"`.
pub fn rtype_name(rtype: u16) -> &'static str {
    match rtype {
        DNS_TYPE_A => "A",
        DNS_TYPE_NS => "NS",
        DNS_TYPE_CNAME => "CNAME",
        DNS_TYPE_SOA => "SOA",
        DNS_TYPE_PTR => "PTR",
        DNS_TYPE_MX => "MX",
        DNS_TYPE_TXT => "TXT",
        DNS_TYPE_AAAA => "AAAA",
        DNS_TYPE_SRV => "SRV",
        DNS_TYPE_OPT => "OPT",
        DNS_TYPE_DS => "DS",
        DNS_TYPE_RRSIG => "RRSIG",
        DNS_TYPE_NSEC => "NSEC",
        DNS_TYPE_DNSKEY => "DNSKEY",
        DNS_TYPE_ANY => "ANY",
        _ => "UNKNOWN",
    }
}

/// Return the canonical textual name for a DNS response code (RCODE).
pub fn rcode_name(rcode: u8) -> &'static str {
    match rcode {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        6 => "YXDOMAIN",
        7 => "YXRRSET",
        8 => "NXRRSET",
        9 => "NOTAUTH",
        10 => "NOTZONE",
        _ => "UNKNOWN",
    }
}

// ---------------------------------------------------------------------------
// Public parsing API
// ---------------------------------------------------------------------------

/// Parse a DNS message from UDP payload (or TCP DNS stream segment after the
/// 2-byte length prefix is stripped).
///
/// Parses all four sections of the DNS message.  EDNS0 OPT pseudo-records in
/// the additional section are silently skipped.
///
/// Returns `None` if the data is shorter than the 12-byte header or the
/// header fields reference offsets beyond the packet boundary.
pub fn parse_dns(data: &[u8]) -> Option<DnsInfo> {
    if data.len() < 12 {
        return None;
    }

    let transaction_id = u16::from_be_bytes([data[0], data[1]]);
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let is_response = flags & 0x8000 != 0;
    let opcode = ((flags >> 11) & 0x0F) as u8;
    let rcode = (flags & 0x000F) as u8;

    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    let nscount = u16::from_be_bytes([data[8], data[9]]) as usize;
    let arcount = u16::from_be_bytes([data[10], data[11]]) as usize;

    let mut offset = 12usize;

    // --- Questions -----------------------------------------------------------
    let mut questions = Vec::with_capacity(qdcount.min(MAX_QUESTIONS));
    for _ in 0..qdcount.min(MAX_QUESTIONS) {
        let (name, new_offset) = read_dns_name(data, offset)?;
        offset = new_offset;

        if offset + 4 > data.len() {
            return None;
        }
        let qtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let qclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        offset += 4;

        questions.push(DnsQuestion { name, qtype, qclass });
    }

    // --- Answer records ------------------------------------------------------
    let mut answers = Vec::new();
    for _ in 0..ancount.min(MAX_RECORDS) {
        match parse_rr(data, offset) {
            Some((record, next)) => {
                offset = next;
                answers.push(record);
            }
            None => break,
        }
    }

    // --- Authority records ---------------------------------------------------
    let mut authorities = Vec::new();
    for _ in 0..nscount.min(MAX_RECORDS) {
        match parse_rr(data, offset) {
            Some((record, next)) => {
                offset = next;
                authorities.push(record);
            }
            None => break,
        }
    }

    // --- Additional records (skip EDNS0 OPT pseudo-records) -----------------
    let mut additionals = Vec::new();
    for _ in 0..arcount.min(MAX_RECORDS) {
        match parse_rr(data, offset) {
            Some((record, next)) => {
                offset = next;
                if record.rtype != DNS_TYPE_OPT {
                    additionals.push(record);
                }
            }
            None => break,
        }
    }

    Some(DnsInfo {
        transaction_id,
        is_response,
        opcode,
        rcode,
        flags,
        questions,
        answers,
        authorities,
        additionals,
    })
}

// ---------------------------------------------------------------------------
// Resource record parsing
// ---------------------------------------------------------------------------

/// Parse one resource record starting at `offset`.
///
/// Returns `(record, offset_after_record)` or `None` on truncation /
/// malformed input.
fn parse_rr(data: &[u8], offset: usize) -> Option<(DnsRecord, usize)> {
    let (name, mut pos) = read_dns_name(data, offset)?;

    // Fixed fields: type(2) + class(2) + ttl(4) + rdlength(2) = 10 bytes.
    if pos + 10 > data.len() {
        return None;
    }

    let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
    let rclass = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
    let ttl = u32::from_be_bytes([
        data[pos + 4],
        data[pos + 5],
        data[pos + 6],
        data[pos + 7],
    ]);
    let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
    pos += 10;

    if pos + rdlength > data.len() {
        return None;
    }

    let rdata = parse_rdata(data, pos, rdlength, rtype);
    pos += rdlength;

    Some((DnsRecord { name, rtype, rclass, ttl, rdata }, pos))
}

/// Parse RDATA for well-known record types; returns `DnsRdata::Unknown` for
/// anything else (or when the rdata bytes are malformed for a known type).
fn parse_rdata(data: &[u8], offset: usize, rdlength: usize, rtype: u16) -> DnsRdata {
    let end = offset + rdlength;

    match rtype {
        // A — 4-byte IPv4 address.
        DNS_TYPE_A => {
            if rdlength == 4 {
                DnsRdata::A(Ipv4Addr::new(
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ))
            } else {
                DnsRdata::Unknown(data[offset..end].to_vec())
            }
        }

        // AAAA — 16-byte IPv6 address.
        DNS_TYPE_AAAA => {
            if rdlength == 16 {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[offset..offset + 16]);
                DnsRdata::Aaaa(Ipv6Addr::from(octets))
            } else {
                DnsRdata::Unknown(data[offset..end].to_vec())
            }
        }

        // CNAME / NS / PTR — a single compressed domain name.
        DNS_TYPE_CNAME => match read_dns_name(data, offset) {
            Some((name, _)) => DnsRdata::Cname(name),
            None => DnsRdata::Unknown(data[offset..end].to_vec()),
        },

        DNS_TYPE_NS => match read_dns_name(data, offset) {
            Some((name, _)) => DnsRdata::Ns(name),
            None => DnsRdata::Unknown(data[offset..end].to_vec()),
        },

        DNS_TYPE_PTR => match read_dns_name(data, offset) {
            Some((name, _)) => DnsRdata::Ptr(name),
            None => DnsRdata::Unknown(data[offset..end].to_vec()),
        },

        // MX — 2-byte preference + compressed domain name.
        DNS_TYPE_MX => {
            if rdlength < 3 {
                return DnsRdata::Unknown(data[offset..end].to_vec());
            }
            let preference = u16::from_be_bytes([data[offset], data[offset + 1]]);
            match read_dns_name(data, offset + 2) {
                Some((exchange, _)) => DnsRdata::Mx { preference, exchange },
                None => DnsRdata::Unknown(data[offset..end].to_vec()),
            }
        }

        // TXT — one or more length-prefixed character strings.
        DNS_TYPE_TXT => {
            let mut strings = Vec::new();
            let mut pos = offset;
            while pos < end {
                if pos >= data.len() {
                    break;
                }
                let slen = data[pos] as usize;
                pos += 1;
                if pos + slen > end || pos + slen > data.len() {
                    break;
                }
                let s = String::from_utf8_lossy(&data[pos..pos + slen]).into_owned();
                strings.push(s);
                pos += slen;
            }
            DnsRdata::Txt(strings)
        }

        // SOA — mname + rname + 5 × u32 fields.
        DNS_TYPE_SOA => {
            let mut pos = offset;

            let (mname, new_pos) = match read_dns_name(data, pos) {
                Some(r) => r,
                None => return DnsRdata::Unknown(data[offset..end].to_vec()),
            };
            pos = new_pos;

            let (rname, new_pos) = match read_dns_name(data, pos) {
                Some(r) => r,
                None => return DnsRdata::Unknown(data[offset..end].to_vec()),
            };
            pos = new_pos;

            // 5 × 4-byte fields = 20 bytes.
            if pos + 20 > data.len() {
                return DnsRdata::Unknown(data[offset..end].to_vec());
            }

            let serial  = u32::from_be_bytes([data[pos],    data[pos+1],  data[pos+2],  data[pos+3]]);
            let refresh = u32::from_be_bytes([data[pos+4],  data[pos+5],  data[pos+6],  data[pos+7]]);
            let retry   = u32::from_be_bytes([data[pos+8],  data[pos+9],  data[pos+10], data[pos+11]]);
            let expire  = u32::from_be_bytes([data[pos+12], data[pos+13], data[pos+14], data[pos+15]]);
            let minimum = u32::from_be_bytes([data[pos+16], data[pos+17], data[pos+18], data[pos+19]]);

            DnsRdata::Soa { mname, rname, serial, refresh, retry, expire, minimum }
        }

        _ => DnsRdata::Unknown(data[offset..end].to_vec()),
    }
}

// ---------------------------------------------------------------------------
// DNS name reader — label decompression (RFC 1035 §4.1.4)
// ---------------------------------------------------------------------------

/// Read a DNS domain name from the wire at `offset`, following compression
/// pointers.  Returns `(name, offset_after_name)` or `None` if the data is
/// malformed or contains a pointer cycle.
fn read_dns_name(data: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut jumped = false;
    let mut return_offset = 0;
    // Track visited offsets to detect pointer cycles.
    let mut seen: HashMap<usize, ()> = HashMap::new();

    loop {
        if offset >= data.len() {
            return None;
        }

        if seen.contains_key(&offset) {
            return None; // cycle detected
        }
        seen.insert(offset, ());

        let len = data[offset] as usize;

        if len == 0 {
            // Root label: name is complete.
            if !jumped {
                return_offset = offset + 1;
            }
            break;
        }

        // Compression pointer (top two bits = 11).
        if len & 0xC0 == 0xC0 {
            if offset + 1 >= data.len() {
                return None;
            }
            if !jumped {
                return_offset = offset + 2;
            }
            let ptr = ((len & 0x3F) << 8) | (data[offset + 1] as usize);
            offset = ptr;
            jumped = true;
            continue;
        }

        // Normal label.
        offset += 1;
        if offset + len > data.len() {
            return None;
        }
        let label = String::from_utf8_lossy(&data[offset..offset + len]).to_string();
        labels.push(label);
        offset += len;
    }

    Some((labels.join("."), return_offset))
}

// ---------------------------------------------------------------------------
// Shannon entropy (used by the DNS-tunneling detector)
// ---------------------------------------------------------------------------

/// Calculate the Shannon entropy (in bits) of the characters in `s`.
pub fn entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq: HashMap<char, usize> = HashMap::new();
    for c in s.chars() {
        *freq.entry(c).or_insert(0) += 1;
    }
    let len = s.len() as f64;
    freq.values()
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // -----------------------------------------------------------------------
    // Helper — build a minimal DNS packet header
    // -----------------------------------------------------------------------

    /// Build a 12-byte DNS header.
    fn header(tx_id: u16, flags: u16, qdcount: u16, ancount: u16, nscount: u16, arcount: u16) -> Vec<u8> {
        let mut h = Vec::with_capacity(12);
        h.extend_from_slice(&tx_id.to_be_bytes());
        h.extend_from_slice(&flags.to_be_bytes());
        h.extend_from_slice(&qdcount.to_be_bytes());
        h.extend_from_slice(&ancount.to_be_bytes());
        h.extend_from_slice(&nscount.to_be_bytes());
        h.extend_from_slice(&arcount.to_be_bytes());
        h
    }

    /// Encode a domain name as DNS wire-format labels (no compression).
    fn wire_name(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0x00); // root
        out
    }

    /// Build a question section entry.
    fn question(name: &str, qtype: u16, qclass: u16) -> Vec<u8> {
        let mut q = wire_name(name);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&qclass.to_be_bytes());
        q
    }

    // -----------------------------------------------------------------------
    // entropy
    // -----------------------------------------------------------------------

    #[test]
    fn test_entropy_empty_string() {
        assert_eq!(entropy(""), 0.0);
    }

    #[test]
    fn test_entropy_single_char_repeated() {
        assert_eq!(entropy("a"), 0.0);
        assert_eq!(entropy("aaaa"), 0.0);
    }

    #[test]
    fn test_entropy_two_equal_symbols() {
        let e = entropy("ab");
        assert!((e - 1.0).abs() < 1e-9, "entropy of 'ab' should be 1.0, got {e}");
    }

    #[test]
    fn test_entropy_high_for_random_looking_string() {
        let e = entropy("aB3xQzRpLmKjNvWs");
        assert!(e > 3.5, "expected high entropy, got {e}");
    }

    #[test]
    fn test_entropy_low_for_repetitive_string() {
        let e = entropy("aaabbbccc");
        assert!(e < 2.0, "expected low entropy for repetitive string, got {e}");
    }

    // -----------------------------------------------------------------------
    // rtype_name / rcode_name
    // -----------------------------------------------------------------------

    #[test]
    fn test_rtype_name_known_types() {
        assert_eq!(rtype_name(DNS_TYPE_A),      "A");
        assert_eq!(rtype_name(DNS_TYPE_NS),     "NS");
        assert_eq!(rtype_name(DNS_TYPE_CNAME),  "CNAME");
        assert_eq!(rtype_name(DNS_TYPE_SOA),    "SOA");
        assert_eq!(rtype_name(DNS_TYPE_PTR),    "PTR");
        assert_eq!(rtype_name(DNS_TYPE_MX),     "MX");
        assert_eq!(rtype_name(DNS_TYPE_TXT),    "TXT");
        assert_eq!(rtype_name(DNS_TYPE_AAAA),   "AAAA");
        assert_eq!(rtype_name(DNS_TYPE_SRV),    "SRV");
        assert_eq!(rtype_name(DNS_TYPE_OPT),    "OPT");
        assert_eq!(rtype_name(DNS_TYPE_DNSKEY), "DNSKEY");
        assert_eq!(rtype_name(DNS_TYPE_ANY),    "ANY");
        assert_eq!(rtype_name(9999),            "UNKNOWN");
    }

    #[test]
    fn test_rcode_name_known_codes() {
        assert_eq!(rcode_name(0),  "NOERROR");
        assert_eq!(rcode_name(1),  "FORMERR");
        assert_eq!(rcode_name(2),  "SERVFAIL");
        assert_eq!(rcode_name(3),  "NXDOMAIN");
        assert_eq!(rcode_name(4),  "NOTIMP");
        assert_eq!(rcode_name(5),  "REFUSED");
        assert_eq!(rcode_name(10), "NOTZONE");
        assert_eq!(rcode_name(99), "UNKNOWN");
    }

    // -----------------------------------------------------------------------
    // parse_dns — header / question section (existing behaviour)
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_dns_too_short_returns_none() {
        assert!(parse_dns(&[]).is_none());
        assert!(parse_dns(&[0u8; 11]).is_none());
    }

    #[test]
    fn test_parse_dns_empty_question_section() {
        let mut data = vec![0u8; 12];
        data[0] = 0xAB;
        data[1] = 0xCD;
        data[2] = 0x01; // RD=1 (standard query)
        data[3] = 0x00;
        // qdcount = 0 (already zeroed)

        let info = parse_dns(&data).expect("parse");
        assert_eq!(info.transaction_id, 0xABCD);
        assert!(!info.is_response);
        assert_eq!(info.rcode, 0);
        assert!(info.questions.is_empty());
        assert!(info.answers.is_empty());
    }

    #[test]
    fn test_parse_dns_standard_query_for_example_com() {
        #[rustfmt::skip]
        let data: Vec<u8> = vec![
            // Header
            0x12, 0x34,              // transaction_id
            0x01, 0x00,              // flags: RD=1 (standard query)
            0x00, 0x01,              // qdcount = 1
            0x00, 0x00,              // ancount = 0
            0x00, 0x00,              // nscount = 0
            0x00, 0x00,              // arcount = 0
            // Question: "example.com"
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,                    // root label
            0x00, 0x01,              // qtype = A
            0x00, 0x01,              // qclass = IN
        ];

        let info = parse_dns(&data).expect("parse dns");
        assert_eq!(info.transaction_id, 0x1234);
        assert!(!info.is_response);
        assert_eq!(info.questions.len(), 1);
        assert_eq!(info.questions[0].name, "example.com");
        assert_eq!(info.questions[0].qtype, 1);  // A
        assert_eq!(info.questions[0].qclass, 1); // IN
        assert!(info.answers.is_empty());
    }

    #[test]
    fn test_parse_dns_response_flag() {
        let mut data = vec![0u8; 12];
        data[2] = 0x80; // QR = 1 (response)
        let info = parse_dns(&data).expect("parse");
        assert!(info.is_response);
    }

    #[test]
    fn test_parse_dns_rcode_nxdomain() {
        let mut data = vec![0u8; 12];
        data[3] = 0x03; // NXDOMAIN
        let info = parse_dns(&data).expect("parse");
        assert_eq!(info.rcode, 3);
    }

    #[test]
    fn test_flags_field_preserved() {
        // flags = 0x8180: QR=1, RD=1, RA=1, RCODE=0
        let mut data = vec![0u8; 12];
        data[2] = 0x81;
        data[3] = 0x80;
        let info = parse_dns(&data).expect("parse");
        assert_eq!(info.flags, 0x8180);
    }

    // -----------------------------------------------------------------------
    // parse_dns — A record answer
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_dns_a_record_response() {
        // Response to "a.bc" query: one A answer = 1.2.3.4, TTL=300.
        // Question name "a.bc" at offset 12 (6 bytes incl. root label).
        // Answer uses a pointer (0xC0 0x0C) back to the question name.
        #[rustfmt::skip]
        let data: Vec<u8> = vec![
            // Header: tx=0x1234 flags=0x8180 qd=1 an=1 ns=0 ar=0
            0x12, 0x34,  0x81, 0x80,  0x00, 0x01,  0x00, 0x01,  0x00, 0x00,  0x00, 0x00,
            // Question: "a.bc" A IN
            0x01, b'a',  0x02, b'b', b'c',  0x00,  0x00, 0x01,  0x00, 0x01,
            // Answer: <ptr→"a.bc"> A IN TTL=300 rdata=1.2.3.4
            0xC0, 0x0C,  0x00, 0x01,  0x00, 0x01,
            0x00, 0x00, 0x01, 0x2C,   // TTL = 300
            0x00, 0x04,               // rdlength = 4
            0x01, 0x02, 0x03, 0x04,   // 1.2.3.4
        ];

        let info = parse_dns(&data).expect("parse");
        assert!(info.is_response);
        assert_eq!(info.answers.len(), 1);

        let rec = &info.answers[0];
        assert_eq!(rec.name, "a.bc");
        assert_eq!(rec.rtype, DNS_TYPE_A);
        assert_eq!(rec.ttl, 300);

        match &rec.rdata {
            DnsRdata::A(addr) => assert_eq!(*addr, Ipv4Addr::new(1, 2, 3, 4)),
            other => panic!("expected A rdata, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // AAAA answer
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_dns_aaaa_record_response() {
        // Response: "a.bc" AAAA ::1 TTL=300
        #[rustfmt::skip]
        let data: Vec<u8> = vec![
            // Header
            0x12, 0x34,  0x81, 0x80,  0x00, 0x01,  0x00, 0x01,  0x00, 0x00,  0x00, 0x00,
            // Question: "a.bc" AAAA IN
            0x01, b'a',  0x02, b'b', b'c',  0x00,  0x00, 0x1C,  0x00, 0x01,
            // Answer: ptr AAAA IN TTL=300 rdlen=16 ::1
            0xC0, 0x0C,  0x00, 0x1C,  0x00, 0x01,
            0x00, 0x00, 0x01, 0x2C,   // TTL = 300
            0x00, 0x10,               // rdlength = 16
            0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1,  // ::1
        ];

        let info = parse_dns(&data).expect("parse");
        assert_eq!(info.answers.len(), 1);
        match &info.answers[0].rdata {
            DnsRdata::Aaaa(addr) => assert_eq!(*addr, Ipv6Addr::new(0,0,0,0,0,0,0,1)),
            other => panic!("expected AAAA rdata, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // CNAME answer
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_dns_cname_response() {
        // Response: "w.bc" CNAME "a.bc"
        // CNAME rdata "a.bc" wire: 0x01 'a' 0x02 'b' 'c' 0x00 = 6 bytes
        #[rustfmt::skip]
        let data: Vec<u8> = vec![
            // Header: qd=1 an=1
            0xAB, 0xCD,  0x81, 0x80,  0x00, 0x01,  0x00, 0x01,  0x00, 0x00,  0x00, 0x00,
            // Question: "w.bc" A IN
            0x01, b'w',  0x02, b'b', b'c',  0x00,  0x00, 0x01,  0x00, 0x01,
            // Answer: ptr CNAME IN TTL=60 rdlen=6 "a.bc"
            0xC0, 0x0C,  0x00, 0x05,  0x00, 0x01,
            0x00, 0x00, 0x00, 0x3C,   // TTL = 60
            0x00, 0x06,               // rdlength = 6
            0x01, b'a',  0x02, b'b', b'c',  0x00,  // "a.bc"
        ];

        let info = parse_dns(&data).expect("parse");
        assert_eq!(info.answers.len(), 1);
        assert_eq!(info.answers[0].rtype, DNS_TYPE_CNAME);
        match &info.answers[0].rdata {
            DnsRdata::Cname(name) => assert_eq!(name, "a.bc"),
            other => panic!("expected Cname rdata, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // NS answer
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_dns_ns_response() {
        // Response: "a.bc" NS "ns1.a.bc"
        // "ns1.a.bc" wire: 0x03 'n' 's' '1'  0x01 'a'  0x02 'b' 'c'  0x00 = 10 bytes
        #[rustfmt::skip]
        let data: Vec<u8> = vec![
            // Header
            0x12, 0x34,  0x81, 0x80,  0x00, 0x01,  0x00, 0x01,  0x00, 0x00,  0x00, 0x00,
            // Question: "a.bc" NS IN
            0x01, b'a',  0x02, b'b', b'c',  0x00,  0x00, 0x02,  0x00, 0x01,
            // Answer: ptr NS IN TTL=86400 rdlen=10 "ns1.a.bc"
            0xC0, 0x0C,  0x00, 0x02,  0x00, 0x01,
            0x00, 0x01, 0x51, 0x80,   // TTL = 86400
            0x00, 0x0A,               // rdlength = 10
            0x03, b'n', b's', b'1',
            0x01, b'a',
            0x02, b'b', b'c',
            0x00,
        ];

        let info = parse_dns(&data).expect("parse");
        assert_eq!(info.answers.len(), 1);
        assert_eq!(info.answers[0].rtype, DNS_TYPE_NS);
        match &info.answers[0].rdata {
            DnsRdata::Ns(name) => assert_eq!(name, "ns1.a.bc"),
            other => panic!("expected Ns rdata, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // PTR answer
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_dns_ptr_response() {
        // Response: "p.bc" PTR "host.a.bc"
        // "host.a.bc" wire: 0x04 'h' 'o' 's' 't'  0x01 'a'  0x02 'b' 'c'  0x00 = 11 bytes
        #[rustfmt::skip]
        let data: Vec<u8> = vec![
            // Header
            0x12, 0x34,  0x81, 0x80,  0x00, 0x01,  0x00, 0x01,  0x00, 0x00,  0x00, 0x00,
            // Question: "p.bc" PTR IN
            0x01, b'p',  0x02, b'b', b'c',  0x00,  0x00, 0x0C,  0x00, 0x01,
            // Answer: ptr PTR IN TTL=3600 rdlen=11 "host.a.bc"
            0xC0, 0x0C,  0x00, 0x0C,  0x00, 0x01,
            0x00, 0x00, 0x0E, 0x10,   // TTL = 3600
            0x00, 0x0B,               // rdlength = 11
            0x04, b'h', b'o', b's', b't',
            0x01, b'a',
            0x02, b'b', b'c',
            0x00,
        ];

        let info = parse_dns(&data).expect("parse");
        assert_eq!(info.answers.len(), 1);
        assert_eq!(info.answers[0].rtype, DNS_TYPE_PTR);
        match &info.answers[0].rdata {
            DnsRdata::Ptr(name) => assert_eq!(name, "host.a.bc"),
            other => panic!("expected Ptr rdata, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // MX answer
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_dns_mx_response() {
        // Response: "a.bc" MX 10 "mail.a.bc"
        // MX rdata: pref(2) + "mail.a.bc"(11 bytes) = 13 bytes
        // "mail.a.bc" wire: 0x04 'm' 'a' 'i' 'l'  0x01 'a'  0x02 'b' 'c'  0x00 = 11 bytes
        #[rustfmt::skip]
        let data: Vec<u8> = vec![
            // Header
            0x12, 0x34,  0x81, 0x80,  0x00, 0x01,  0x00, 0x01,  0x00, 0x00,  0x00, 0x00,
            // Question: "a.bc" MX IN
            0x01, b'a',  0x02, b'b', b'c',  0x00,  0x00, 0x0F,  0x00, 0x01,
            // Answer: ptr MX IN TTL=3600 rdlen=13  pref=10 "mail.a.bc"
            0xC0, 0x0C,  0x00, 0x0F,  0x00, 0x01,
            0x00, 0x00, 0x0E, 0x10,   // TTL = 3600
            0x00, 0x0D,               // rdlength = 13
            0x00, 0x0A,               // preference = 10
            0x04, b'm', b'a', b'i', b'l',
            0x01, b'a',
            0x02, b'b', b'c',
            0x00,
        ];

        let info = parse_dns(&data).expect("parse");
        assert_eq!(info.answers.len(), 1);
        assert_eq!(info.answers[0].rtype, DNS_TYPE_MX);
        match &info.answers[0].rdata {
            DnsRdata::Mx { preference, exchange } => {
                assert_eq!(*preference, 10);
                assert_eq!(exchange, "mail.a.bc");
            }
            other => panic!("expected Mx rdata, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // TXT answer — single string and multi-string
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_dns_txt_response_single_string() {
        // Response: "a.bc" TXT "hello"  (rdlength = 6: 1-byte len + 5 chars)
        #[rustfmt::skip]
        let data: Vec<u8> = vec![
            // Header
            0x12, 0x34,  0x81, 0x80,  0x00, 0x01,  0x00, 0x01,  0x00, 0x00,  0x00, 0x00,
            // Question: "a.bc" TXT IN
            0x01, b'a',  0x02, b'b', b'c',  0x00,  0x00, 0x10,  0x00, 0x01,
            // Answer: ptr TXT IN TTL=60 rdlen=6  0x05 "hello"
            0xC0, 0x0C,  0x00, 0x10,  0x00, 0x01,
            0x00, 0x00, 0x00, 0x3C,   // TTL = 60
            0x00, 0x06,               // rdlength = 6
            0x05, b'h', b'e', b'l', b'l', b'o',
        ];

        let info = parse_dns(&data).expect("parse");
        match &info.answers[0].rdata {
            DnsRdata::Txt(strings) => {
                assert_eq!(strings.len(), 1);
                assert_eq!(strings[0], "hello");
            }
            other => panic!("expected Txt rdata, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_dns_txt_response_multiple_strings() {
        // TXT record with two strings: "foo" and "bar"
        // rdlength = (1+3) + (1+3) = 8
        #[rustfmt::skip]
        let data: Vec<u8> = vec![
            // Header
            0x12, 0x34,  0x81, 0x80,  0x00, 0x01,  0x00, 0x01,  0x00, 0x00,  0x00, 0x00,
            // Question
            0x01, b'a',  0x02, b'b', b'c',  0x00,  0x00, 0x10,  0x00, 0x01,
            // Answer
            0xC0, 0x0C,  0x00, 0x10,  0x00, 0x01,
            0x00, 0x00, 0x00, 0x3C,
            0x00, 0x08,               // rdlength = 8
            0x03, b'f', b'o', b'o',
            0x03, b'b', b'a', b'r',
        ];

        let info = parse_dns(&data).expect("parse");
        match &info.answers[0].rdata {
            DnsRdata::Txt(strings) => {
                assert_eq!(strings, &["foo", "bar"]);
            }
            other => panic!("expected Txt rdata, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // SOA answer
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_dns_soa_response() {
        // SOA: mname="ns1.a.bc"(10) rname="admin.a.bc"(12) + 20 bytes = 42 bytes
        #[rustfmt::skip]
        let data: Vec<u8> = vec![
            // Header
            0x12, 0x34,  0x81, 0x80,  0x00, 0x01,  0x00, 0x01,  0x00, 0x00,  0x00, 0x00,
            // Question: "a.bc" SOA IN
            0x01, b'a',  0x02, b'b', b'c',  0x00,  0x00, 0x06,  0x00, 0x01,
            // Answer: ptr SOA IN TTL=3600 rdlen=42
            0xC0, 0x0C,  0x00, 0x06,  0x00, 0x01,
            0x00, 0x00, 0x0E, 0x10,   // TTL = 3600
            0x00, 0x2A,               // rdlength = 42
            // mname = "ns1.a.bc" (10 bytes)
            0x03, b'n', b's', b'1',  0x01, b'a',  0x02, b'b', b'c',  0x00,
            // rname = "admin.a.bc" (12 bytes)
            0x05, b'a', b'd', b'm', b'i', b'n',  0x01, b'a',  0x02, b'b', b'c',  0x00,
            // serial  = 2024010101 = 0x78A3F175
            0x78, 0xA3, 0xF1, 0x75,
            // refresh = 86400 = 0x00015180
            0x00, 0x01, 0x51, 0x80,
            // retry   = 7200  = 0x00001C20
            0x00, 0x00, 0x1C, 0x20,
            // expire  = 3600000 = 0x0036EE80
            0x00, 0x36, 0xEE, 0x80,
            // minimum = 3600 = 0x00000E10
            0x00, 0x00, 0x0E, 0x10,
        ];

        let info = parse_dns(&data).expect("parse");
        assert_eq!(info.answers.len(), 1);
        assert_eq!(info.answers[0].rtype, DNS_TYPE_SOA);
        match &info.answers[0].rdata {
            DnsRdata::Soa { mname, rname, serial, refresh, retry, expire, minimum } => {
                assert_eq!(mname, "ns1.a.bc");
                assert_eq!(rname, "admin.a.bc");
                assert_eq!(*serial,  2024010101);
                assert_eq!(*refresh, 86400);
                assert_eq!(*retry,   7200);
                assert_eq!(*expire,  3600000);
                assert_eq!(*minimum, 3600);
            }
            other => panic!("expected Soa rdata, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Multiple answer records
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_dns_multiple_a_answers() {
        // Two A records: 1.1.1.1 and 2.2.2.2
        #[rustfmt::skip]
        let data: Vec<u8> = vec![
            // Header: qd=1 an=2
            0x12, 0x34,  0x81, 0x80,  0x00, 0x01,  0x00, 0x02,  0x00, 0x00,  0x00, 0x00,
            // Question
            0x01, b'a',  0x02, b'b', b'c',  0x00,  0x00, 0x01,  0x00, 0x01,
            // Answer 1: 1.1.1.1
            0xC0, 0x0C,  0x00, 0x01,  0x00, 0x01,
            0x00, 0x00, 0x00, 0x3C,  0x00, 0x04,  1, 1, 1, 1,
            // Answer 2: 2.2.2.2
            0xC0, 0x0C,  0x00, 0x01,  0x00, 0x01,
            0x00, 0x00, 0x00, 0x3C,  0x00, 0x04,  2, 2, 2, 2,
        ];

        let info = parse_dns(&data).expect("parse");
        assert_eq!(info.answers.len(), 2);
        match &info.answers[0].rdata {
            DnsRdata::A(addr) => assert_eq!(*addr, Ipv4Addr::new(1, 1, 1, 1)),
            other => panic!("unexpected: {other:?}"),
        }
        match &info.answers[1].rdata {
            DnsRdata::A(addr) => assert_eq!(*addr, Ipv4Addr::new(2, 2, 2, 2)),
            other => panic!("unexpected: {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // NXDOMAIN response (no answers)
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_dns_nxdomain_response() {
        // Flags 0x8183: QR=1, RD=1, RA=1, RCODE=3 (NXDOMAIN)
        #[rustfmt::skip]
        let data: Vec<u8> = vec![
            // Header
            0x12, 0x34,  0x81, 0x83,  0x00, 0x01,  0x00, 0x00,  0x00, 0x00,  0x00, 0x00,
            // Question
            0x01, b'a',  0x02, b'b', b'c',  0x00,  0x00, 0x01,  0x00, 0x01,
        ];

        let info = parse_dns(&data).expect("parse");
        assert!(info.is_response);
        assert_eq!(info.rcode, 3);
        assert_eq!(rcode_name(info.rcode), "NXDOMAIN");
        assert!(info.answers.is_empty());
    }

    // -----------------------------------------------------------------------
    // Label compression pointer in question name
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_dns_label_compression_in_answer_name() {
        // Packet where the answer RR name uses a pointer into the question name.
        // Already covered by A-record test; verify the pointer resolves correctly.
        #[rustfmt::skip]
        let data: Vec<u8> = vec![
            0x00, 0x01,  0x81, 0x80,  0x00, 0x01,  0x00, 0x01,  0x00, 0x00,  0x00, 0x00,
            // "x.yz" at offset 12
            0x01, b'x',  0x02, b'y', b'z',  0x00,  0x00, 0x01,  0x00, 0x01,
            // Answer name = pointer to offset 12 = "x.yz"
            0xC0, 0x0C,  0x00, 0x01,  0x00, 0x01,
            0x00, 0x00, 0x00, 0x01,  0x00, 0x04,  10, 20, 30, 40,
        ];

        let info = parse_dns(&data).expect("parse");
        assert_eq!(info.answers[0].name, "x.yz");
        match &info.answers[0].rdata {
            DnsRdata::A(addr) => assert_eq!(*addr, Ipv4Addr::new(10, 20, 30, 40)),
            other => panic!("{other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Wire-name helper round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn test_wire_name_helper_round_trip() {
        let encoded = wire_name("sub.example.com");
        // Should decode back to "sub.example.com"
        let mut pkt = vec![0u8; 12]; // fake header
        pkt.extend_from_slice(&encoded);
        let (name, _) = read_dns_name(&pkt, 12).expect("read_dns_name");
        assert_eq!(name, "sub.example.com");
    }

    // -----------------------------------------------------------------------
    // Unknown rdata preserved as raw bytes
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_dns_unknown_rtype_preserved_as_raw_bytes() {
        // rtype = 9999 (unknown) with 3-byte rdata
        #[rustfmt::skip]
        let data: Vec<u8> = vec![
            0x00, 0x01,  0x81, 0x80,  0x00, 0x01,  0x00, 0x01,  0x00, 0x00,  0x00, 0x00,
            0x01, b'a',  0x02, b'b', b'c',  0x00,  0x00, 0x01,  0x00, 0x01,
            // Answer: rtype = 0x270F (9999), rdlen=3, rdata=AA BB CC
            0xC0, 0x0C,  0x27, 0x0F,  0x00, 0x01,
            0x00, 0x00, 0x00, 0x01,  0x00, 0x03,  0xAA, 0xBB, 0xCC,
        ];

        let info = parse_dns(&data).expect("parse");
        assert_eq!(info.answers[0].rtype, 9999);
        match &info.answers[0].rdata {
            DnsRdata::Unknown(bytes) => assert_eq!(bytes, &[0xAA, 0xBB, 0xCC]),
            other => panic!("expected Unknown rdata, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Authority section
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_dns_authority_section() {
        // NXDOMAIN response with one SOA in the authority section.
        // We reuse the SOA bytes from the SOA test but put it in ns=1.
        #[rustfmt::skip]
        let data: Vec<u8> = vec![
            // Header: qd=1 an=0 ns=1 ar=0
            0x12, 0x34,  0x81, 0x83,  0x00, 0x01,  0x00, 0x00,  0x00, 0x01,  0x00, 0x00,
            // Question
            0x01, b'a',  0x02, b'b', b'c',  0x00,  0x00, 0x01,  0x00, 0x01,
            // Authority SOA: ptr SOA IN TTL=3600 rdlen=42
            0xC0, 0x0C,  0x00, 0x06,  0x00, 0x01,
            0x00, 0x00, 0x0E, 0x10,
            0x00, 0x2A,
            0x03, b'n', b's', b'1',  0x01, b'a',  0x02, b'b', b'c',  0x00,
            0x05, b'a', b'd', b'm', b'i', b'n',  0x01, b'a',  0x02, b'b', b'c',  0x00,
            0x00, 0x00, 0x00, 0x01,
            0x00, 0x01, 0x51, 0x80,
            0x00, 0x00, 0x1C, 0x20,
            0x00, 0x36, 0xEE, 0x80,
            0x00, 0x00, 0x0E, 0x10,
        ];

        let info = parse_dns(&data).expect("parse");
        assert!(info.answers.is_empty());
        assert_eq!(info.authorities.len(), 1);
        assert_eq!(info.authorities[0].rtype, DNS_TYPE_SOA);
    }

    // -----------------------------------------------------------------------
    // opcode extraction
    // -----------------------------------------------------------------------

    #[test]
    fn test_opcode_extracted_from_flags() {
        // flags = 0x2800 → QR=0, opcode=5, rest=0
        let mut data = vec![0u8; 12];
        data[2] = 0x28; // 0b00101000 → bits[14:11] = 0101 = 5
        data[3] = 0x00;
        let info = parse_dns(&data).expect("parse");
        assert_eq!(info.opcode, 5);
    }
}
