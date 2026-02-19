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
