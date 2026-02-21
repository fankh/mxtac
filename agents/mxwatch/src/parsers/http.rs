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

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // parse_http_request
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_valid_get_request() {
        let raw = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/7.88\r\n\r\n";
        let info = parse_http_request(raw).expect("parse");
        assert_eq!(info.method, "GET");
        assert_eq!(info.uri, "/index.html");
        assert_eq!(info.version, "HTTP/1.1");
        assert_eq!(info.host.as_deref(), Some("example.com"));
        assert_eq!(info.user_agent.as_deref(), Some("curl/7.88"));
        assert!(info.content_length.is_none());
    }

    #[test]
    fn test_parse_post_with_content_length() {
        let raw = b"POST /api/data HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 42\r\n\r\n";
        let info = parse_http_request(raw).expect("parse");
        assert_eq!(info.method, "POST");
        assert_eq!(info.uri, "/api/data");
        assert_eq!(info.content_length, Some(42));
    }

    #[test]
    fn test_parse_non_http_returns_none() {
        // SSH banner — not an HTTP request.
        assert!(parse_http_request(b"SSH-2.0-OpenSSH_8.9\r\n").is_none());
        // Empty
        assert!(parse_http_request(b"").is_none());
        // Binary data
        assert!(parse_http_request(&[0x00, 0xFF, 0x80]).is_none());
    }

    #[test]
    fn test_parse_all_known_methods() {
        for method in &["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"] {
            let raw = format!("{method} / HTTP/1.0\r\n\r\n");
            let info = parse_http_request(raw.as_bytes()).expect(method);
            assert_eq!(info.method, *method);
        }
    }

    // -----------------------------------------------------------------------
    // is_suspicious_request
    // -----------------------------------------------------------------------

    #[test]
    fn test_suspicious_directory_traversal() {
        let info = HttpInfo {
            method: "GET".into(),
            uri: "/files/../../etc/passwd".into(),
            version: "HTTP/1.1".into(),
            host: None,
            user_agent: None,
            content_length: None,
        };
        assert!(is_suspicious_request(&info, &[]));
    }

    #[test]
    fn test_suspicious_command_injection_semicolon() {
        let info = HttpInfo {
            method: "GET".into(),
            uri: "/search?q=foo;id".into(),
            version: "HTTP/1.1".into(),
            host: None,
            user_agent: None,
            content_length: None,
        };
        assert!(is_suspicious_request(&info, &[]));
    }

    #[test]
    fn test_suspicious_sql_union_select() {
        // The detector matches the literal "UNION SELECT" (space-separated).
        let info = HttpInfo {
            method: "GET".into(),
            uri: "/item?id=1 UNION SELECT NULL,NULL--".into(),
            version: "HTTP/1.1".into(),
            host: None,
            user_agent: None,
            content_length: None,
        };
        assert!(is_suspicious_request(&info, &[]));
    }

    #[test]
    fn test_suspicious_custom_pattern() {
        let info = HttpInfo {
            method: "GET".into(),
            uri: "/wp-admin/install.php".into(),
            version: "HTTP/1.1".into(),
            host: None,
            user_agent: None,
            content_length: None,
        };
        let patterns = vec!["wp-admin".to_string()];
        assert!(is_suspicious_request(&info, &patterns));
    }

    #[test]
    fn test_normal_request_not_suspicious() {
        let info = HttpInfo {
            method: "GET".into(),
            uri: "/api/v1/health".into(),
            version: "HTTP/1.1".into(),
            host: Some("api.example.com".into()),
            user_agent: Some("myapp/1.0".into()),
            content_length: None,
        };
        assert!(!is_suspicious_request(&info, &[]));
    }
}
