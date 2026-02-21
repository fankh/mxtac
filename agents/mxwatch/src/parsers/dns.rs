//! Minimal DNS parser.
//!
//! Parses enough of the DNS wire format to extract query names, types,
//! and response codes without pulling in a full DNS library.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Extracted DNS metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsInfo {
    pub transaction_id: u16,
    pub is_response: bool,
    pub opcode: u8,
    pub rcode: u8,
    pub questions: Vec<DnsQuestion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// Try to parse a DNS packet from the UDP payload.
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

    let mut offset = 12;
    let mut questions = Vec::with_capacity(qdcount);

    for _ in 0..qdcount {
        let (name, new_offset) = read_dns_name(data, offset)?;
        offset = new_offset;

        if offset + 4 > data.len() {
            return None;
        }
        let qtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let qclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        offset += 4;

        questions.push(DnsQuestion {
            name,
            qtype,
            qclass,
        });
    }

    Some(DnsInfo {
        transaction_id,
        is_response,
        opcode,
        rcode,
        questions,
    })
}

/// Read a DNS domain name from the wire (handles label compression).
fn read_dns_name(data: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut jumped = false;
    let mut return_offset = 0;
    let mut seen: HashMap<usize, ()> = HashMap::new();

    loop {
        if offset >= data.len() {
            return None;
        }

        // Prevent infinite loops from pointer cycles.
        if seen.contains_key(&offset) {
            return None;
        }
        seen.insert(offset, ());

        let len = data[offset] as usize;

        if len == 0 {
            if !jumped {
                return_offset = offset + 1;
            }
            break;
        }

        // Pointer (compression).
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

    let name = labels.join(".");
    Some((name, return_offset))
}

/// Calculate Shannon entropy of a string.
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

    // -----------------------------------------------------------------------
    // entropy
    // -----------------------------------------------------------------------

    #[test]
    fn test_entropy_empty_string() {
        assert_eq!(entropy(""), 0.0);
    }

    #[test]
    fn test_entropy_single_char_repeated() {
        // All identical characters → 0 bits of entropy.
        assert_eq!(entropy("a"), 0.0);
        assert_eq!(entropy("aaaa"), 0.0);
    }

    #[test]
    fn test_entropy_two_equal_symbols() {
        // "ab" → p(a)=0.5, p(b)=0.5 → entropy = 1.0 bit
        let e = entropy("ab");
        assert!((e - 1.0).abs() < 1e-9, "entropy of 'ab' should be 1.0, got {e}");
    }

    #[test]
    fn test_entropy_high_for_random_looking_string() {
        // Strings that look like base64-encoded data have high entropy.
        let e = entropy("aB3xQzRpLmKjNvWs");
        assert!(e > 3.5, "expected high entropy, got {e}");
    }

    #[test]
    fn test_entropy_low_for_repetitive_string() {
        let e = entropy("aaabbbccc");
        assert!(e < 2.0, "expected low entropy for repetitive string, got {e}");
    }

    // -----------------------------------------------------------------------
    // parse_dns
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_dns_too_short_returns_none() {
        assert!(parse_dns(&[]).is_none());
        assert!(parse_dns(&[0u8; 11]).is_none());
    }

    #[test]
    fn test_parse_dns_empty_question_section() {
        // Minimal DNS header with qdcount = 0.
        let mut data = vec![0u8; 12];
        data[0] = 0xAB; // transaction ID hi
        data[1] = 0xCD; // transaction ID lo
        data[2] = 0x01; // flags hi (QR=0, standard query)
        data[3] = 0x00; // flags lo (rcode=0)
        // qdcount = 0 (already zeroed)

        let info = parse_dns(&data).expect("parse");
        assert_eq!(info.transaction_id, 0xABCD);
        assert!(!info.is_response);
        assert_eq!(info.rcode, 0);
        assert!(info.questions.is_empty());
    }

    #[test]
    fn test_parse_dns_standard_query_for_example_com() {
        // Hand-crafted DNS query for "example.com" type A.
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
}
