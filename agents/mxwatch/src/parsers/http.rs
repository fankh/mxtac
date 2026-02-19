//! Minimal HTTP request parser.
//!
//! Inspects TCP payload bytes to detect HTTP request methods and extract
//! request lines.  Does not attempt full HTTP/1.1 parsing.

use serde::{Deserialize, Serialize};

/// Extracted HTTP request metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpInfo {
    pub method: String,
    pub uri: String,
    pub version: String,
    pub host: Option<String>,
    pub user_agent: Option<String>,
    pub content_length: Option<usize>,
}

/// Known HTTP methods used to identify whether a payload starts with HTTP.
const HTTP_METHODS: &[&str] = &[
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE",
];

/// Try to parse an HTTP request from a raw TCP payload.
pub fn parse_http_request(data: &[u8]) -> Option<HttpInfo> {
    let text = std::str::from_utf8(data).ok()?;

    // Check that the payload starts with a known HTTP method.
    let starts_with_method = HTTP_METHODS.iter().any(|m| text.starts_with(m));
    if !starts_with_method {
        return None;
    }

    let mut lines = text.lines();
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let uri = parts.next()?.to_string();
    let version = parts.next().unwrap_or("HTTP/1.0").to_string();

    let mut host = None;
    let mut user_agent = None;
    let mut content_length = None;

    for line in lines {
        if line.is_empty() {
            break; // End of headers.
        }
        if let Some((key, value)) = line.split_once(':') {
            let key_lower = key.trim().to_lowercase();
            let value = value.trim().to_string();
            match key_lower.as_str() {
                "host" => host = Some(value),
                "user-agent" => user_agent = Some(value),
                "content-length" => content_length = value.parse().ok(),
                _ => {}
            }
        }
    }

    Some(HttpInfo {
        method,
        uri,
        version,
        host,
        user_agent,
        content_length,
    })
}

/// Check if an HTTP request looks suspicious based on common attack patterns.
pub fn is_suspicious_request(info: &HttpInfo, extra_patterns: &[String]) -> bool {
    let uri = &info.uri;

    // Directory traversal.
    if uri.contains("../") || uri.contains("..\\") {
        return true;
    }
    // Command injection.
    if uri.contains(';') || uri.contains('|') || uri.contains('`') {
        return true;
    }
    // SQL injection hints.
    let upper = uri.to_uppercase();
    if upper.contains("' OR ") || upper.contains("UNION SELECT") || upper.contains("DROP TABLE") {
        return true;
    }
    // Custom patterns from config.
    for pattern in extra_patterns {
        if uri.contains(pattern.as_str()) {
            return true;
        }
    }
    false
}
