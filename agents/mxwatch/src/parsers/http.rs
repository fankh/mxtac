//! HTTP/1.x protocol parser — feature 25.6.
//!
//! Parses both HTTP/1.0 and HTTP/1.1 **requests** and **responses** from raw
//! TCP payload bytes.  Designed for NDR (network detection and response) use
//! cases: visibility into plaintext HTTP traffic, suspicious pattern
//! detection, and OCSF event enrichment.
//!
//! # Capabilities
//! - Auto-detects request vs. response from the start line.
//! - Parses the start line (method + URI, or status code + reason).
//! - Extracts 13 well-known headers; counts all others up to [`MAX_HEADERS`].
//! - Flags truncated messages where the header section ends without a blank line.
//! - Detects common web-attack patterns in request URIs and User-Agent strings.
//! - Provides port and status-code helper predicates.
//!
//! # Limitations
//! - HTTP/1.x text format only; HTTP/2 (binary framing) is not handled.
//! - Header-only parsing; message bodies are not inspected.
//! - Operates on a single TCP segment; multi-segment reassembly is out of scope.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Safety limits
// ---------------------------------------------------------------------------

/// Maximum number of header lines to parse from one HTTP message.
const MAX_HEADERS: usize = 100;

// ---------------------------------------------------------------------------
// HTTP method list (used to identify the start of a request)
// ---------------------------------------------------------------------------

const HTTP_METHODS: &[&str] = &[
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE",
];

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Direction of the HTTP message relative to the client/server relationship.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HttpDirection {
    /// Client-to-server message: request line + request headers.
    Request,
    /// Server-to-client message: status line + response headers.
    Response,
}

/// Parsed HTTP/1.x message metadata (request **or** response).
///
/// Fields that are not applicable to the current direction are `None` or empty.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpInfo {
    /// Whether this is a client request or a server response.
    pub direction: HttpDirection,

    // ---- Request start line ------------------------------------------------
    /// HTTP method (`GET`, `POST`, …). Present only for requests.
    pub method: Option<String>,
    /// Request URI (`/path?query=value`). Present only for requests.
    pub uri: Option<String>,

    // ---- Response start line -----------------------------------------------
    /// HTTP status code (200, 301, 404, …). Present only for responses.
    pub status_code: Option<u16>,
    /// HTTP status reason phrase (`OK`, `Not Found`, …). Present only for responses.
    pub status_text: Option<String>,

    // ---- Common start-line field -------------------------------------------
    /// HTTP version from the start line (`HTTP/1.0` or `HTTP/1.1`).
    pub version: String,

    // ---- Headers -----------------------------------------------------------
    /// `Host` header (request) or origin domain.
    pub host: Option<String>,
    /// `User-Agent` header.
    pub user_agent: Option<String>,
    /// `Content-Length` header parsed as `usize`.
    pub content_length: Option<usize>,
    /// `Content-Type` header (e.g. `application/json`).
    pub content_type: Option<String>,
    /// `Referer` (or `Referrer`) header.
    pub referer: Option<String>,
    /// `Cookie` request header (raw value, may contain multiple cookies).
    pub cookie: Option<String>,
    /// All `Set-Cookie` response header values (one entry per header line).
    pub set_cookie: Vec<String>,
    /// `Authorization` request header (e.g. `Bearer <token>`).
    pub authorization: Option<String>,
    /// `Transfer-Encoding` header (e.g. `chunked`).
    pub transfer_encoding: Option<String>,
    /// `Location` response header used in redirects.
    pub location: Option<String>,
    /// `Server` response header (server software identification).
    pub server: Option<String>,
    /// `X-Forwarded-For` header (client IP behind a proxy).
    pub x_forwarded_for: Option<String>,
    /// `Connection` header (`keep-alive`, `close`).
    pub connection: Option<String>,

    /// Total number of header lines parsed (including unrecognized ones).
    pub header_count: usize,
    /// `true` if a blank line terminating the headers was found in the payload.
    /// `false` means the TCP segment was truncated before the end of headers.
    pub headers_complete: bool,
}

// ---------------------------------------------------------------------------
// Public parsing API
// ---------------------------------------------------------------------------

/// Auto-detect and parse an HTTP/1.x message (request **or** response).
///
/// Returns `None` if `data` is not valid UTF-8 or does not start with a
/// known HTTP method or the `HTTP/` version prefix.
pub fn parse_http(data: &[u8]) -> Option<HttpInfo> {
    let text = std::str::from_utf8(data).ok()?;

    if text.starts_with("HTTP/") {
        parse_http_response_inner(text)
    } else if HTTP_METHODS.iter().any(|m| text.starts_with(m)) {
        parse_http_request_inner(text)
    } else {
        None
    }
}

/// Parse an HTTP/1.x **request** from a raw TCP payload.
///
/// Returns `None` if the payload does not start with a known HTTP method, or
/// if it starts with `HTTP/` (i.e. it is a response, not a request).
///
/// This is a convenience wrapper around [`parse_http`] that filters to the
/// [`HttpDirection::Request`] variant only.
pub fn parse_http_request(data: &[u8]) -> Option<HttpInfo> {
    let info = parse_http(data)?;
    if info.direction == HttpDirection::Request { Some(info) } else { None }
}

/// Parse an HTTP/1.x **response** from a raw TCP payload.
///
/// Returns `None` if the payload does not start with `HTTP/`.
///
/// This is a convenience wrapper around [`parse_http`] that filters to the
/// [`HttpDirection::Response`] variant only.
pub fn parse_http_response(data: &[u8]) -> Option<HttpInfo> {
    let info = parse_http(data)?;
    if info.direction == HttpDirection::Response { Some(info) } else { None }
}

// ---------------------------------------------------------------------------
// Suspicion checks
// ---------------------------------------------------------------------------

/// Return `true` if an HTTP **request** shows signs of malicious or anomalous
/// activity.
///
/// Detection categories:
/// - **Directory traversal**: `../` or `..\` in the URI.
/// - **Command injection**: `;`, `|`, `` ` `` in the URI.
/// - **SQL injection hints**: `' OR `, `UNION SELECT`, `DROP TABLE`.
/// - **Null-byte injection**: `%00` or a literal NUL in the URI.
/// - **PHP webshell markers**: `.php?cmd=`, `passthru`, `system(`.
/// - **Scanner User-Agents**: sqlmap, nikto, dirbuster, nmap, masscan.
/// - **POST without User-Agent** (anomalous for legitimate clients).
/// - **Custom patterns** from the TOML configuration.
///
/// Always returns `false` for responses (call [`is_suspicious_response`] for
/// response-side checks).
pub fn is_suspicious_request(info: &HttpInfo, extra_patterns: &[String]) -> bool {
    if info.direction != HttpDirection::Request {
        return false;
    }

    if let Some(uri) = &info.uri {
        // Directory traversal.
        if uri.contains("../") || uri.contains("..\\") {
            return true;
        }
        // Command injection.
        if uri.contains(';') || uri.contains('|') || uri.contains('`') {
            return true;
        }
        // SQL injection hints — check raw and URL-encoded (`+` / `%20`) variants
        // because HTTP clients percent-encode spaces in query strings.
        let upper = uri.to_uppercase();
        if upper.contains("' OR ")
            || upper.contains("UNION SELECT")
            || upper.contains("UNION+SELECT")
            || upper.contains("UNION%20SELECT")
            || upper.contains("DROP TABLE")
            || upper.contains("DROP+TABLE")
            || upper.contains("DROP%20TABLE")
        {
            return true;
        }
        // Null-byte injection (URL-encoded or literal).
        if uri.contains("%00") || uri.contains('\0') {
            return true;
        }
        // PHP webshell common patterns.
        if upper.contains(".PHP?CMD=")
            || upper.contains("PASSTHRU")
            || upper.contains("SYSTEM(")
        {
            return true;
        }
        // Custom patterns supplied via configuration.
        for pattern in extra_patterns {
            if uri.contains(pattern.as_str()) {
                return true;
            }
        }
    }

    // Suspicious or absent User-Agent.
    if let Some(ua) = &info.user_agent {
        if ua.is_empty() {
            return true;
        }
        let ua_lower = ua.to_lowercase();
        if ua_lower.contains("sqlmap")
            || ua_lower.contains("nikto")
            || ua_lower.contains("dirbuster")
            || ua_lower.contains("nmap")
            || ua_lower.contains("masscan")
        {
            return true;
        }
    } else if info.method.as_deref() == Some("POST") {
        // POST without a User-Agent header is anomalous for legitimate clients.
        return true;
    }

    false
}

/// Return `true` if an HTTP **response** shows signs of suspicious server
/// behaviour.
///
/// Detection categories:
/// - **Very large non-media responses**: `Content-Length` > 10 MB and
///   `Content-Type` is not audio, video, image, or zip — may indicate data
///   exfiltration.
/// - **Obsolete server software**: Apache/1.x or IIS/5–6 (long unsupported,
///   often associated with unpatched CVEs).
///
/// Always returns `false` for requests.
pub fn is_suspicious_response(info: &HttpInfo) -> bool {
    if info.direction != HttpDirection::Response {
        return false;
    }

    // Unusually large response body with a non-media Content-Type.
    if let (Some(len), Some(ct)) = (info.content_length, &info.content_type) {
        let ct_lower = ct.to_lowercase();
        if len > 10_000_000
            && !ct_lower.contains("video")
            && !ct_lower.contains("audio")
            && !ct_lower.contains("image")
            && !ct_lower.contains("zip")
            && !ct_lower.contains("octet-stream")
        {
            return true;
        }
    }

    // Responses from obsolete / vulnerable server software versions.
    if let Some(server) = &info.server {
        let s = server.to_lowercase();
        if s.contains("apache/1.") || s.contains("iis/5.") || s.contains("iis/6.") {
            return true;
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Port and status-code helpers
// ---------------------------------------------------------------------------

/// Return `true` if `port` is a well-known HTTP or HTTPS port.
///
/// Covers: 80 (HTTP), 443 (HTTPS), 8000, 8008, 8080, 8443, 8888.
pub fn is_http_port(port: u16) -> bool {
    matches!(port, 80 | 443 | 8000 | 8008 | 8080 | 8443 | 8888)
}

/// Return `true` if the HTTP status code indicates a redirect (3xx).
pub fn status_is_redirect(code: u16) -> bool {
    (300..=399).contains(&code)
}

/// Return `true` if the HTTP status code indicates a client or server error
/// (4xx or 5xx).
pub fn status_is_error(code: u16) -> bool {
    code >= 400
}

// ---------------------------------------------------------------------------
// Internal parsers
// ---------------------------------------------------------------------------

/// Parse an HTTP/1.x request from a UTF-8 text slice.
fn parse_http_request_inner(text: &str) -> Option<HttpInfo> {
    let mut lines = text.lines();
    let request_line = lines.next()?;

    // Parse: METHOD URI HTTP/VERSION
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let uri = parts.next()?.to_string();
    let version = parts.next().unwrap_or("HTTP/1.0").to_string();

    let (h, header_count, headers_complete) = parse_headers(&mut lines);

    Some(HttpInfo {
        direction: HttpDirection::Request,
        method: Some(method),
        uri: Some(uri),
        status_code: None,
        status_text: None,
        version,
        host: h.host,
        user_agent: h.user_agent,
        content_length: h.content_length,
        content_type: h.content_type,
        referer: h.referer,
        cookie: h.cookie,
        set_cookie: h.set_cookie,
        authorization: h.authorization,
        transfer_encoding: h.transfer_encoding,
        location: h.location,
        server: h.server,
        x_forwarded_for: h.x_forwarded_for,
        connection: h.connection,
        header_count,
        headers_complete,
    })
}

/// Parse an HTTP/1.x response from a UTF-8 text slice.
fn parse_http_response_inner(text: &str) -> Option<HttpInfo> {
    let mut lines = text.lines();
    let status_line = lines.next()?;

    // Parse: HTTP/VERSION CODE REASON (reason phrase may contain spaces)
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next()?.to_string();
    let code_str = parts.next()?;
    let status_code: u16 = code_str.trim().parse().ok()?;
    let status_text = parts.next().unwrap_or("").trim().to_string();

    let (h, header_count, headers_complete) = parse_headers(&mut lines);

    Some(HttpInfo {
        direction: HttpDirection::Response,
        method: None,
        uri: None,
        status_code: Some(status_code),
        status_text: if status_text.is_empty() { None } else { Some(status_text) },
        version,
        host: h.host,
        user_agent: h.user_agent,
        content_length: h.content_length,
        content_type: h.content_type,
        referer: h.referer,
        cookie: h.cookie,
        set_cookie: h.set_cookie,
        authorization: h.authorization,
        transfer_encoding: h.transfer_encoding,
        location: h.location,
        server: h.server,
        x_forwarded_for: h.x_forwarded_for,
        connection: h.connection,
        header_count,
        headers_complete,
    })
}

// ---------------------------------------------------------------------------
// Header parsing
// ---------------------------------------------------------------------------

/// Accumulator for all well-known parsed headers.
#[derive(Default)]
struct ParsedHeaders {
    host: Option<String>,
    user_agent: Option<String>,
    content_length: Option<usize>,
    content_type: Option<String>,
    referer: Option<String>,
    cookie: Option<String>,
    set_cookie: Vec<String>,
    authorization: Option<String>,
    transfer_encoding: Option<String>,
    location: Option<String>,
    server: Option<String>,
    x_forwarded_for: Option<String>,
    connection: Option<String>,
}

/// Parse HTTP header lines from a line iterator.
///
/// Returns `(headers, count, complete)` where:
/// - `headers` holds the parsed well-known values.
/// - `count` is the total number of header lines seen (capped at
///   [`MAX_HEADERS`]).
/// - `complete` is `true` when a blank line terminating the header section
///   was found; `false` means the payload ended before the blank line.
fn parse_headers<'a>(lines: &mut impl Iterator<Item = &'a str>) -> (ParsedHeaders, usize, bool) {
    let mut h = ParsedHeaders::default();
    let mut count = 0usize;
    let mut complete = false;

    for line in lines {
        // A blank line (CRLF produces an empty string after .lines()) marks
        // the end of the header section.
        if line.is_empty() {
            complete = true;
            break;
        }
        if count >= MAX_HEADERS {
            // Stop counting but mark as incomplete so callers know we hit the limit.
            break;
        }
        count += 1;

        // Split on the first colon only; header values may contain colons
        // (e.g. URLs in Location, URIs in Authorization).
        let Some((key, value)) = line.split_once(':') else { continue };
        let key_lower = key.trim().to_lowercase();
        let value = value.trim().to_string();

        match key_lower.as_str() {
            "host"               => h.host = Some(value),
            "user-agent"         => h.user_agent = Some(value),
            "content-length"     => h.content_length = value.parse().ok(),
            "content-type"       => h.content_type = Some(value),
            // Accept both RFC spelling variants.
            "referer" | "referrer" => h.referer = Some(value),
            "cookie"             => h.cookie = Some(value),
            // Multiple Set-Cookie lines are valid; accumulate all of them.
            "set-cookie"         => h.set_cookie.push(value),
            "authorization"      => h.authorization = Some(value),
            "transfer-encoding"  => h.transfer_encoding = Some(value),
            "location"           => h.location = Some(value),
            "server"             => h.server = Some(value),
            "x-forwarded-for"    => h.x_forwarded_for = Some(value),
            "connection"         => h.connection = Some(value),
            _ => {} // unrecognized header: counted but not stored
        }
    }

    (h, count, complete)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Build a minimal GET request byte string.
    fn get_request(uri: &str, extra_headers: &str) -> Vec<u8> {
        format!(
            "GET {uri} HTTP/1.1\r\nHost: example.com\r\n{extra_headers}\r\n"
        )
        .into_bytes()
    }

    /// Build a minimal POST request byte string.
    fn post_request(uri: &str, extra_headers: &str) -> Vec<u8> {
        format!(
            "POST {uri} HTTP/1.1\r\nHost: example.com\r\nUser-Agent: myapp/1.0\r\n{extra_headers}\r\n"
        )
        .into_bytes()
    }

    /// Build a minimal HTTP response byte string.
    fn response(status: u16, reason: &str, extra_headers: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 {status} {reason}\r\n{extra_headers}\r\n"
        )
        .into_bytes()
    }

    // -----------------------------------------------------------------------
    // parse_http_request — start line
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_request_get_start_line() {
        let raw = b"GET /index.html HTTP/1.1\r\nHost: h.com\r\n\r\n";
        let info = parse_http_request(raw).expect("parse");
        assert_eq!(info.direction, HttpDirection::Request);
        assert_eq!(info.method.as_deref(), Some("GET"));
        assert_eq!(info.uri.as_deref(), Some("/index.html"));
        assert_eq!(info.version, "HTTP/1.1");
        assert!(info.status_code.is_none());
        assert!(info.status_text.is_none());
    }

    #[test]
    fn test_parse_request_http10_fallback() {
        // When the version token is missing, defaults to HTTP/1.0.
        let raw = b"HEAD / \r\n\r\n";
        let info = parse_http_request(raw).expect("parse");
        assert_eq!(info.version, "HTTP/1.0");
    }

    #[test]
    fn test_parse_request_all_standard_methods() {
        for method in &["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"] {
            let raw = format!("{method} / HTTP/1.1\r\n\r\n");
            let info = parse_http_request(raw.as_bytes())
                .unwrap_or_else(|| panic!("expected parse for {method}"));
            assert_eq!(info.method.as_deref(), Some(*method));
        }
    }

    #[test]
    fn test_parse_request_connect_method() {
        let raw = b"CONNECT proxy.example.com:443 HTTP/1.1\r\nHost: proxy.example.com:443\r\n\r\n";
        let info = parse_http_request(raw).expect("parse CONNECT");
        assert_eq!(info.method.as_deref(), Some("CONNECT"));
    }

    // -----------------------------------------------------------------------
    // parse_http_request — header extraction
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_request_basic_headers() {
        let raw = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/7.88\r\n\r\n";
        let info = parse_http_request(raw).expect("parse");
        assert_eq!(info.host.as_deref(), Some("example.com"));
        assert_eq!(info.user_agent.as_deref(), Some("curl/7.88"));
        assert!(info.content_length.is_none());
    }

    #[test]
    fn test_parse_request_content_length() {
        let raw = b"POST /api HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 42\r\n\r\n";
        let info = parse_http_request(raw).expect("parse");
        assert_eq!(info.content_length, Some(42));
    }

    #[test]
    fn test_parse_request_content_type() {
        let raw = post_request("/data", "Content-Type: application/json\r\n");
        let info = parse_http_request(&raw).expect("parse");
        assert_eq!(info.content_type.as_deref(), Some("application/json"));
    }

    #[test]
    fn test_parse_request_referer() {
        let raw = get_request("/page", "Referer: https://google.com/search\r\n");
        let info = parse_http_request(&raw).expect("parse");
        assert_eq!(info.referer.as_deref(), Some("https://google.com/search"));
    }

    #[test]
    fn test_parse_request_referrer_alternate_spelling() {
        // RFC 7231 allows "Referrer" as well as "Referer".
        let raw = get_request("/page", "Referrer: https://origin.com/\r\n");
        let info = parse_http_request(&raw).expect("parse");
        assert_eq!(info.referer.as_deref(), Some("https://origin.com/"));
    }

    #[test]
    fn test_parse_request_cookie() {
        let raw = get_request("/", "Cookie: session=abc123; user=alice\r\n");
        let info = parse_http_request(&raw).expect("parse");
        assert_eq!(info.cookie.as_deref(), Some("session=abc123; user=alice"));
    }

    #[test]
    fn test_parse_request_authorization() {
        let raw = get_request("/secure", "Authorization: Bearer tok-secret\r\n");
        let info = parse_http_request(&raw).expect("parse");
        assert_eq!(info.authorization.as_deref(), Some("Bearer tok-secret"));
    }

    #[test]
    fn test_parse_request_x_forwarded_for() {
        let raw = get_request("/", "X-Forwarded-For: 203.0.113.5\r\n");
        let info = parse_http_request(&raw).expect("parse");
        assert_eq!(info.x_forwarded_for.as_deref(), Some("203.0.113.5"));
    }

    #[test]
    fn test_parse_request_connection_header() {
        let raw = get_request("/", "Connection: keep-alive\r\n");
        let info = parse_http_request(&raw).expect("parse");
        assert_eq!(info.connection.as_deref(), Some("keep-alive"));
    }

    #[test]
    fn test_parse_request_transfer_encoding() {
        let raw = post_request("/upload", "Transfer-Encoding: chunked\r\n");
        let info = parse_http_request(&raw).expect("parse");
        assert_eq!(info.transfer_encoding.as_deref(), Some("chunked"));
    }

    #[test]
    fn test_parse_request_headers_complete_flag() {
        let raw = b"GET / HTTP/1.1\r\nHost: h.com\r\n\r\n";
        let info = parse_http_request(raw).expect("parse");
        assert!(info.headers_complete, "blank line present → complete");
    }

    #[test]
    fn test_parse_request_truncated_no_blank_line() {
        // No trailing \r\n\r\n — simulates a truncated TCP segment.
        let raw = b"GET / HTTP/1.1\r\nHost: h.com";
        let info = parse_http_request(raw).expect("parse");
        assert!(!info.headers_complete, "no blank line → truncated");
    }

    #[test]
    fn test_parse_request_header_count() {
        let raw = b"GET / HTTP/1.1\r\nHost: h.com\r\nUser-Agent: ua\r\nAccept: */*\r\n\r\n";
        let info = parse_http_request(raw).expect("parse");
        assert_eq!(info.header_count, 3);
    }

    // -----------------------------------------------------------------------
    // parse_http_request — rejection cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_request_returns_none_for_non_http() {
        assert!(parse_http_request(b"SSH-2.0-OpenSSH_8.9\r\n").is_none());
        assert!(parse_http_request(b"").is_none());
        assert!(parse_http_request(&[0x00, 0xFF, 0x80]).is_none());
    }

    #[test]
    fn test_parse_request_returns_none_for_response() {
        // A response payload must not be returned by parse_http_request.
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        assert!(parse_http_request(raw).is_none());
    }

    // -----------------------------------------------------------------------
    // parse_http_response — start line
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_response_200_ok() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let info = parse_http_response(raw).expect("parse");
        assert_eq!(info.direction, HttpDirection::Response);
        assert_eq!(info.status_code, Some(200));
        assert_eq!(info.status_text.as_deref(), Some("OK"));
        assert_eq!(info.version, "HTTP/1.1");
        assert!(info.method.is_none());
        assert!(info.uri.is_none());
    }

    #[test]
    fn test_parse_response_404_not_found() {
        let raw = b"HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\n";
        let info = parse_http_response(raw).expect("parse");
        assert_eq!(info.status_code, Some(404));
        assert_eq!(info.status_text.as_deref(), Some("Not Found"));
    }

    #[test]
    fn test_parse_response_301_moved_permanently_with_location() {
        let raw = b"HTTP/1.1 301 Moved Permanently\r\nLocation: https://example.com/new\r\n\r\n";
        let info = parse_http_response(raw).expect("parse");
        assert_eq!(info.status_code, Some(301));
        assert_eq!(info.location.as_deref(), Some("https://example.com/new"));
    }

    #[test]
    fn test_parse_response_multi_reason_phrase() {
        // Reason phrase with multiple words.
        let raw = b"HTTP/1.1 503 Service Unavailable\r\n\r\n";
        let info = parse_http_response(raw).expect("parse");
        assert_eq!(info.status_code, Some(503));
        assert_eq!(info.status_text.as_deref(), Some("Service Unavailable"));
    }

    #[test]
    fn test_parse_response_10_version() {
        let raw = b"HTTP/1.0 200 OK\r\n\r\n";
        let info = parse_http_response(raw).expect("parse");
        assert_eq!(info.version, "HTTP/1.0");
    }

    // -----------------------------------------------------------------------
    // parse_http_response — header extraction
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_response_server_header() {
        let raw = response(200, "OK", "Server: nginx/1.24\r\n");
        let info = parse_http_response(&raw).expect("parse");
        assert_eq!(info.server.as_deref(), Some("nginx/1.24"));
    }

    #[test]
    fn test_parse_response_content_type() {
        let raw = response(200, "OK", "Content-Type: text/html; charset=utf-8\r\n");
        let info = parse_http_response(&raw).expect("parse");
        assert_eq!(info.content_type.as_deref(), Some("text/html; charset=utf-8"));
    }

    #[test]
    fn test_parse_response_multiple_set_cookie() {
        let raw = b"HTTP/1.1 200 OK\r\nSet-Cookie: a=1; Path=/\r\nSet-Cookie: b=2; HttpOnly\r\n\r\n";
        let info = parse_http_response(raw).expect("parse");
        assert_eq!(info.set_cookie.len(), 2);
        assert_eq!(info.set_cookie[0], "a=1; Path=/");
        assert_eq!(info.set_cookie[1], "b=2; HttpOnly");
    }

    #[test]
    fn test_parse_response_transfer_encoding_chunked() {
        let raw = response(200, "OK", "Transfer-Encoding: chunked\r\n");
        let info = parse_http_response(&raw).expect("parse");
        assert_eq!(info.transfer_encoding.as_deref(), Some("chunked"));
    }

    // -----------------------------------------------------------------------
    // parse_http_response — rejection cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_response_returns_none_for_request() {
        let raw = b"GET / HTTP/1.1\r\nHost: h.com\r\n\r\n";
        assert!(parse_http_response(raw).is_none());
    }

    #[test]
    fn test_parse_response_returns_none_for_garbage() {
        assert!(parse_http_response(b"\x00\x01\x02").is_none());
        assert!(parse_http_response(b"").is_none());
    }

    #[test]
    fn test_parse_response_invalid_status_code() {
        // "ABC" cannot be parsed as u16 → None.
        let raw = b"HTTP/1.1 ABC OK\r\n\r\n";
        assert!(parse_http_response(raw).is_none());
    }

    // -----------------------------------------------------------------------
    // parse_http — unified auto-detect
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_http_detects_request() {
        let raw = b"POST /submit HTTP/1.1\r\nHost: h.com\r\n\r\n";
        let info = parse_http(raw).expect("parse");
        assert_eq!(info.direction, HttpDirection::Request);
    }

    #[test]
    fn test_parse_http_detects_response() {
        let raw = b"HTTP/1.1 204 No Content\r\n\r\n";
        let info = parse_http(raw).expect("parse");
        assert_eq!(info.direction, HttpDirection::Response);
    }

    #[test]
    fn test_parse_http_returns_none_for_unknown() {
        assert!(parse_http(b"SMTP 220 mail.example.com\r\n").is_none());
    }

    // -----------------------------------------------------------------------
    // is_suspicious_request — URI patterns
    // -----------------------------------------------------------------------

    #[test]
    fn test_suspicious_directory_traversal_unix() {
        let raw = get_request("/files/../../etc/passwd", "User-Agent: curl\r\n");
        let info = parse_http_request(&raw).unwrap();
        assert!(is_suspicious_request(&info, &[]));
    }

    #[test]
    fn test_suspicious_directory_traversal_windows() {
        let raw = get_request("/files/..\\..\\windows\\system32", "User-Agent: curl\r\n");
        let info = parse_http_request(&raw).unwrap();
        assert!(is_suspicious_request(&info, &[]));
    }

    #[test]
    fn test_suspicious_command_injection_semicolon() {
        let raw = get_request("/search?q=foo;id", "User-Agent: curl\r\n");
        let info = parse_http_request(&raw).unwrap();
        assert!(is_suspicious_request(&info, &[]));
    }

    #[test]
    fn test_suspicious_command_injection_pipe() {
        let raw = get_request("/cmd?arg=|ls", "User-Agent: curl\r\n");
        let info = parse_http_request(&raw).unwrap();
        assert!(is_suspicious_request(&info, &[]));
    }

    #[test]
    fn test_suspicious_command_injection_backtick() {
        let raw = get_request("/q?x=`id`", "User-Agent: curl\r\n");
        let info = parse_http_request(&raw).unwrap();
        assert!(is_suspicious_request(&info, &[]));
    }

    #[test]
    fn test_suspicious_sql_union_select() {
        // Spaces in URIs must be `+`-encoded; raw spaces would truncate the URI
        // at the first space during request-line parsing.
        let raw = get_request("/item?id=1+UNION+SELECT+NULL,NULL--", "User-Agent: curl\r\n");
        let info = parse_http_request(&raw).unwrap();
        assert!(is_suspicious_request(&info, &[]));
    }

    #[test]
    fn test_suspicious_sql_union_select_percent_encoded() {
        let raw = get_request("/item?id=1%20UNION%20SELECT%20NULL,NULL--", "User-Agent: curl\r\n");
        let info = parse_http_request(&raw).unwrap();
        assert!(is_suspicious_request(&info, &[]));
    }

    #[test]
    fn test_suspicious_sql_drop_table() {
        let raw = get_request("/x?q=DROP+TABLE+users", "User-Agent: curl\r\n");
        let info = parse_http_request(&raw).unwrap();
        assert!(is_suspicious_request(&info, &[]));
    }

    #[test]
    fn test_suspicious_null_byte_url_encoded() {
        let raw = get_request("/file%00.php", "User-Agent: curl\r\n");
        let info = parse_http_request(&raw).unwrap();
        assert!(is_suspicious_request(&info, &[]));
    }

    #[test]
    fn test_suspicious_php_webshell_cmd() {
        let raw = get_request("/shell.php?cmd=whoami", "User-Agent: curl\r\n");
        let info = parse_http_request(&raw).unwrap();
        assert!(is_suspicious_request(&info, &[]));
    }

    #[test]
    fn test_suspicious_custom_pattern() {
        let raw = get_request("/wp-admin/install.php", "User-Agent: curl\r\n");
        let info = parse_http_request(&raw).unwrap();
        let patterns = vec!["wp-admin".to_string()];
        assert!(is_suspicious_request(&info, &patterns));
    }

    #[test]
    fn test_suspicious_scanner_user_agent_sqlmap() {
        let raw = get_request("/search", "User-Agent: sqlmap/1.7\r\n");
        let info = parse_http_request(&raw).unwrap();
        assert!(is_suspicious_request(&info, &[]));
    }

    #[test]
    fn test_suspicious_scanner_user_agent_nikto() {
        let raw = get_request("/", "User-Agent: Nikto/2.1\r\n");
        let info = parse_http_request(&raw).unwrap();
        assert!(is_suspicious_request(&info, &[]));
    }

    #[test]
    fn test_suspicious_post_without_user_agent() {
        let raw = b"POST /api HTTP/1.1\r\nHost: h.com\r\nContent-Length: 10\r\n\r\n";
        let info = parse_http_request(raw).unwrap();
        // POST without any User-Agent header is anomalous.
        assert!(is_suspicious_request(&info, &[]));
    }

    #[test]
    fn test_not_suspicious_normal_get() {
        let raw = get_request("/api/v1/health", "User-Agent: myapp/2.0\r\n");
        let info = parse_http_request(&raw).unwrap();
        assert!(!is_suspicious_request(&info, &[]));
    }

    #[test]
    fn test_suspicious_request_returns_false_for_response() {
        // Passing a response to is_suspicious_request must always return false.
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let info = parse_http_response(raw).unwrap();
        assert!(!is_suspicious_request(&info, &[]));
    }

    // -----------------------------------------------------------------------
    // is_suspicious_response
    // -----------------------------------------------------------------------

    #[test]
    fn test_suspicious_response_old_apache() {
        let raw = response(200, "OK", "Server: Apache/1.3.27 (Unix)\r\n");
        let info = parse_http_response(&raw).unwrap();
        assert!(is_suspicious_response(&info));
    }

    #[test]
    fn test_suspicious_response_old_iis6() {
        let raw = response(200, "OK", "Server: Microsoft-IIS/6.0\r\n");
        let info = parse_http_response(&raw).unwrap();
        assert!(is_suspicious_response(&info));
    }

    #[test]
    fn test_suspicious_response_large_text_payload() {
        // 11 MB text/plain response — potential exfiltration.
        let headers = format!("Content-Length: {}\r\nContent-Type: text/plain\r\n", 11_000_000);
        let raw = response(200, "OK", &headers);
        let info = parse_http_response(&raw).unwrap();
        assert!(is_suspicious_response(&info));
    }

    #[test]
    fn test_not_suspicious_response_large_video() {
        // Large video response is expected; should not trigger.
        let headers = format!("Content-Length: {}\r\nContent-Type: video/mp4\r\n", 50_000_000);
        let raw = response(200, "OK", &headers);
        let info = parse_http_response(&raw).unwrap();
        assert!(!is_suspicious_response(&info));
    }

    #[test]
    fn test_not_suspicious_response_normal() {
        let raw = response(200, "OK", "Server: nginx/1.24\r\nContent-Length: 512\r\n");
        let info = parse_http_response(&raw).unwrap();
        assert!(!is_suspicious_response(&info));
    }

    #[test]
    fn test_suspicious_response_returns_false_for_request() {
        let raw = b"GET / HTTP/1.1\r\nHost: h.com\r\n\r\n";
        let info = parse_http_request(raw).unwrap();
        assert!(!is_suspicious_response(&info));
    }

    // -----------------------------------------------------------------------
    // Port and status-code helpers
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_http_port_standard_ports() {
        assert!(is_http_port(80));
        assert!(is_http_port(443));
        assert!(is_http_port(8080));
        assert!(is_http_port(8000));
        assert!(is_http_port(8443));
        assert!(is_http_port(8888));
        assert!(is_http_port(8008));
    }

    #[test]
    fn test_is_http_port_non_http_ports() {
        assert!(!is_http_port(22));   // SSH
        assert!(!is_http_port(53));   // DNS
        assert!(!is_http_port(3306)); // MySQL
        assert!(!is_http_port(0));
    }

    #[test]
    fn test_status_is_redirect() {
        assert!(status_is_redirect(301));
        assert!(status_is_redirect(302));
        assert!(status_is_redirect(303));
        assert!(status_is_redirect(307));
        assert!(status_is_redirect(308));
        assert!(!status_is_redirect(200));
        assert!(!status_is_redirect(404));
    }

    #[test]
    fn test_status_is_error() {
        assert!(status_is_error(400));
        assert!(status_is_error(401));
        assert!(status_is_error(403));
        assert!(status_is_error(404));
        assert!(status_is_error(500));
        assert!(status_is_error(503));
        assert!(!status_is_error(200));
        assert!(!status_is_error(301));
    }
}
