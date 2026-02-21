//! Authentication event collector.
//!
//! Tails `/var/log/auth.log` (Debian/Ubuntu) and/or `/var/log/secure`
//! (RHEL/CentOS/Fedora) for login events and emits OCSF Authentication
//! Activity (class_uid 3002, category 3 — Identity & Access Management) events.
//!
//! ## Design
//!
//! Each configured log path is opened once and seeked to its current end of
//! file so that pre-existing content is skipped on startup.  On every poll
//! interval new lines are read, parsed, and converted to OCSF events.
//!
//! Only **complete** lines (ending with `\n`) are processed; partial lines
//! buffered at EOF are deferred to the next poll cycle.
//!
//! ## Supported log patterns
//!
//! | Source | Log fragment                                        | Outcome       |
//! |--------|-----------------------------------------------------|---------------|
//! | sshd   | `Accepted password for USER from IP port PORT`      | Logon success |
//! | sshd   | `Accepted publickey for USER from IP port PORT`     | Logon success |
//! | sshd   | `Failed password for USER from IP port PORT`        | Logon failure |
//! | sshd   | `Failed publickey for USER from IP port PORT`       | Logon failure |
//! | sshd   | `Invalid user USER from IP`                         | Logon failure |
//! | sshd   | `session opened for user USER`                      | Logon success |
//! | sshd   | `session closed for user USER`                      | Logoff        |
//! | sudo   | `USER : … COMMAND=CMD`                              | Logon success |
//! | su     | `Successful su for USER`                            | Logon success |
//! | PAM    | `authentication failure`                            | Logon failure |

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};

use crate::collectors::Collector;
use crate::config::AuthCollectorConfig;
use crate::events::ocsf::{AuthenticationActivityData, OcsfDevice, OcsfEvent, OcsfSeverity};

// ---------------------------------------------------------------------------
// Collector struct
// ---------------------------------------------------------------------------

/// Collector that tails authentication log files for login/logoff events.
pub struct AuthCollector {
    config: AuthCollectorConfig,
    device: OcsfDevice,
}

impl AuthCollector {
    pub fn new(config: &AuthCollectorConfig, device: OcsfDevice) -> Self {
        Self {
            config: config.clone(),
            device,
        }
    }
}

// ---------------------------------------------------------------------------
// Collector impl
// ---------------------------------------------------------------------------

#[async_trait]
impl Collector for AuthCollector {
    fn name(&self) -> &'static str {
        "auth"
    }

    async fn run(
        &self,
        tx: mpsc::Sender<OcsfEvent>,
        mut shutdown: watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        info!(
            "Auth collector started (interval={}ms, paths={:?})",
            self.config.poll_interval_ms, self.config.log_paths
        );
        let interval = Duration::from_millis(self.config.poll_interval_ms);

        // Open each configured log file and seek to EOF so we only tail new lines.
        let mut file_readers: HashMap<String, BufReader<File>> = HashMap::new();
        for path in &self.config.log_paths {
            match File::open(path) {
                Ok(mut f) => {
                    let end = f.seek(SeekFrom::End(0)).unwrap_or(0);
                    info!("Auth collector tailing {path} from offset {end}");
                    file_readers.insert(path.clone(), BufReader::new(f));
                }
                Err(e) => {
                    warn!("Auth collector: cannot open {path}: {e}");
                }
            }
        }

        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = shutdown.changed() => {
                    info!("Auth collector shutting down");
                    return Ok(());
                }
            }

            // Collect events synchronously from all readers, then send asynchronously.
            let mut pending: Vec<OcsfEvent> = Vec::new();

            for (path, reader) in &mut file_readers {
                let mut line = String::new();
                loop {
                    line.clear();
                    match reader.read_line(&mut line) {
                        Ok(0) => break, // EOF — no new data this cycle
                        Ok(_) => {
                            // Defer partial lines (no trailing newline) to the next poll.
                            if !line.ends_with('\n') {
                                // Rewind so the partial line is re-read next cycle.
                                let rewind = line.len() as i64;
                                let _ = reader.seek_relative(-rewind);
                                break;
                            }
                            let trimmed = line.trim_end();
                            if let Some(data) = parse_auth_line(trimmed) {
                                let severity = classify_auth_severity(&data);
                                let (activity, activity_id) = auth_activity(&data);
                                let techniques = crate::attack::tag_auth_event(&data);
                                debug!(
                                    user = %data.user,
                                    status = %data.status,
                                    method = %data.auth_method,
                                    "Auth event from {path}"
                                );
                                pending.push(OcsfEvent::authentication_activity(
                                    self.device.clone(),
                                    activity,
                                    activity_id,
                                    severity,
                                    data,
                                )
                                .with_attack_techniques(techniques));
                            }
                        }
                        Err(e) => {
                            warn!("Auth collector read error on {path}: {e}");
                            break;
                        }
                    }
                }
            }

            for event in pending {
                if tx.send(event).await.is_err() {
                    debug!("Event channel closed, stopping auth collector");
                    return Ok(());
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Log line parser
// ---------------------------------------------------------------------------

/// Parse a single syslog line and return an `AuthenticationActivityData` if it
/// matches a known authentication pattern.  Returns `None` for unrecognised
/// lines.
pub(crate) fn parse_auth_line(line: &str) -> Option<AuthenticationActivityData> {
    // SSH: successful authentication
    if line.contains("Accepted password for ") {
        return parse_ssh_accepted(line, "password");
    }
    if line.contains("Accepted publickey for ") {
        return parse_ssh_accepted(line, "publickey");
    }

    // SSH: failed authentication
    if line.contains("Failed password for ") {
        return parse_ssh_failed(line, "password");
    }
    if line.contains("Failed publickey for ") {
        return parse_ssh_failed(line, "publickey");
    }

    // SSH: unknown user attempt
    if line.contains("Invalid user ") {
        return parse_invalid_user(line);
    }

    // PAM session lifecycle
    if line.contains("session opened for user ") {
        return parse_session_opened(line);
    }
    if line.contains("session closed for user ") {
        return parse_session_closed(line);
    }

    // sudo privilege escalation
    if line.contains("COMMAND=") {
        return parse_sudo_command(line);
    }

    // su successful substitution
    if line.contains("Successful su for ") {
        return parse_su_success(line);
    }

    // PAM authentication failure (catch-all)
    if line.contains("authentication failure") {
        return parse_pam_failure(line);
    }

    None
}

// ---------------------------------------------------------------------------
// Pattern-specific parsers (pub(crate) for unit testing)
// ---------------------------------------------------------------------------

pub(crate) fn parse_ssh_accepted(line: &str, method: &str) -> Option<AuthenticationActivityData> {
    let pattern = if method == "password" {
        "Accepted password for "
    } else {
        "Accepted publickey for "
    };
    let rest = extract_after(line, pattern)?;
    let (user, source_ip, source_port) = parse_user_from_ip_port(rest);
    Some(AuthenticationActivityData {
        user,
        source_ip,
        source_port,
        auth_method: method.to_string(),
        status: "Success".into(),
        outcome: "Logon".into(),
        service: extract_service(line),
    })
}

pub(crate) fn parse_ssh_failed(line: &str, method: &str) -> Option<AuthenticationActivityData> {
    let pattern = if method == "password" {
        "Failed password for "
    } else {
        "Failed publickey for "
    };
    let rest = extract_after(line, pattern)?;
    // Normalise "invalid user USER from …" → "USER from …"
    let rest = rest.strip_prefix("invalid user ").unwrap_or(rest);
    let (user, source_ip, source_port) = parse_user_from_ip_port(rest);
    Some(AuthenticationActivityData {
        user,
        source_ip,
        source_port,
        auth_method: method.to_string(),
        status: "Failure".into(),
        outcome: "Logon".into(),
        service: extract_service(line),
    })
}

pub(crate) fn parse_invalid_user(line: &str) -> Option<AuthenticationActivityData> {
    let rest = extract_after(line, "Invalid user ")?;
    // "USER from IP" or just "USER"
    let parts: Vec<&str> = rest.split_whitespace().collect();
    let user = parts.first().copied().unwrap_or("unknown").to_string();
    let source_ip = if parts.len() >= 3 && parts[1] == "from" {
        Some(parts[2].to_string())
    } else {
        None
    };
    Some(AuthenticationActivityData {
        user,
        source_ip,
        source_port: None,
        auth_method: "unknown".into(),
        status: "Failure".into(),
        outcome: "Logon".into(),
        service: extract_service(line),
    })
}

pub(crate) fn parse_session_opened(line: &str) -> Option<AuthenticationActivityData> {
    let rest = extract_after(line, "session opened for user ")?;
    let user = rest.split_whitespace().next().unwrap_or("unknown").to_string();
    Some(AuthenticationActivityData {
        user,
        source_ip: None,
        source_port: None,
        auth_method: "session".into(),
        status: "Success".into(),
        outcome: "Logon".into(),
        service: extract_service(line),
    })
}

pub(crate) fn parse_session_closed(line: &str) -> Option<AuthenticationActivityData> {
    let rest = extract_after(line, "session closed for user ")?;
    let user = rest.split_whitespace().next().unwrap_or("unknown").to_string();
    Some(AuthenticationActivityData {
        user,
        source_ip: None,
        source_port: None,
        auth_method: "session".into(),
        status: "Success".into(),
        outcome: "Logoff".into(),
        service: extract_service(line),
    })
}

pub(crate) fn parse_sudo_command(line: &str) -> Option<AuthenticationActivityData> {
    // sudo log format (with or without PID brackets):
    //   "... sudo[pid]:  USER : TTY=pts/0 ; PWD=/dir ; USER=root ; COMMAND=/bin/ls"
    //   "... sudo:  USER : TTY=pts/0 ; …"
    // The username is the first token in the message body.
    let message = extract_message(line)?;
    let user = message.split_whitespace().next().unwrap_or("unknown").to_string();
    Some(AuthenticationActivityData {
        user,
        source_ip: None,
        source_port: None,
        auth_method: "sudo".into(),
        status: "Success".into(),
        outcome: "Logon".into(),
        service: "sudo".into(),
    })
}

pub(crate) fn parse_su_success(line: &str) -> Option<AuthenticationActivityData> {
    // "Successful su for USER by CALLER"
    let rest = extract_after(line, "Successful su for ")?;
    let user = rest.split_whitespace().next().unwrap_or("unknown").to_string();
    Some(AuthenticationActivityData {
        user,
        source_ip: None,
        source_port: None,
        auth_method: "su".into(),
        status: "Success".into(),
        outcome: "Logon".into(),
        service: extract_service(line),
    })
}

pub(crate) fn parse_pam_failure(line: &str) -> Option<AuthenticationActivityData> {
    // Typical: "pam_unix(sshd:auth): authentication failure; logname= uid=0 … user=alice rhost=1.2.3.4"
    let user = extract_kv(line, "user=").unwrap_or_else(|| "unknown".into());
    let source_ip = extract_kv(line, "rhost=");
    Some(AuthenticationActivityData {
        user,
        source_ip,
        source_port: None,
        auth_method: "pam".into(),
        status: "Failure".into(),
        outcome: "Logon".into(),
        service: extract_service(line),
    })
}

// ---------------------------------------------------------------------------
// OCSF helpers
// ---------------------------------------------------------------------------

/// Map an `AuthenticationActivityData` to its OCSF `(activity_name, activity_id)`.
///
/// OCSF Authentication Activity IDs:
/// * 1 — Logon
/// * 2 — Logoff
pub(crate) fn auth_activity(data: &AuthenticationActivityData) -> (&'static str, u32) {
    match data.outcome.as_str() {
        "Logoff" => ("Logoff", 2),
        _ => ("Logon", 1),
    }
}

/// Assign OCSF severity based on authentication outcome and method.
pub(crate) fn classify_auth_severity(data: &AuthenticationActivityData) -> OcsfSeverity {
    if data.status == "Failure" {
        return OcsfSeverity::Medium;
    }
    if data.auth_method == "sudo" || data.auth_method == "su" {
        // Privilege escalation is noteworthy even when successful.
        return OcsfSeverity::Low;
    }
    OcsfSeverity::Informational
}

// ---------------------------------------------------------------------------
// Syslog line helpers
// ---------------------------------------------------------------------------

/// Return the substring of `line` that starts immediately after `pattern`.
fn extract_after<'a>(line: &'a str, pattern: &str) -> Option<&'a str> {
    line.find(pattern).map(|pos| &line[pos + pattern.len()..])
}

/// Extract the service / program name from a syslog-formatted line.
///
/// Handles both:
/// * `… sshd[1234]: message` — finds the word before `[pid]:`
/// * `… sudo: message`       — finds the word before a bare `:`
pub(crate) fn extract_service(line: &str) -> String {
    // Priority: look for the "service[pid]:" pattern.
    if let Some(bracket_pos) = line.find("]:") {
        let before = &line[..bracket_pos];
        if let Some(open_pos) = before.rfind('[') {
            if let Some(service) = before[..open_pos].split_whitespace().last() {
                return service.to_string();
            }
        }
    }

    // Fallback: syslog without PID — skip 4 tokens (month day time hostname)
    // and take the word before the first `:`.
    let mut skip = 4usize;
    let mut start = 0usize;
    for (i, c) in line.char_indices() {
        if c == ' ' {
            skip -= 1;
            if skip == 0 {
                start = i + 1;
                break;
            }
        }
    }
    let rest = &line[start..];
    if let Some(colon_pos) = rest.find(':') {
        return rest[..colon_pos].trim().to_string();
    }

    "unknown".into()
}

/// Extract the message body after `]:` (with PID) or the first `: ` (without).
pub(crate) fn extract_message(line: &str) -> Option<String> {
    // "service[pid]: message"
    if let Some(pos) = line.find("]: ") {
        return Some(line[pos + 3..].to_string());
    }
    // "service: message"
    if let Some(pos) = line.find(": ") {
        return Some(line[pos + 2..].to_string());
    }
    None
}

/// Parse `"USER from IP port PORT …"` into `(user, Option<ip>, Option<port>)`.
pub(crate) fn parse_user_from_ip_port(s: &str) -> (String, Option<String>, Option<u16>) {
    let parts: Vec<&str> = s.split_whitespace().collect();
    let user = parts.first().copied().unwrap_or("unknown").to_string();

    let from_idx = parts.iter().position(|&w| w == "from");
    let source_ip = from_idx
        .and_then(|i| parts.get(i + 1))
        .map(|s| s.to_string());

    let port_idx = parts.iter().position(|&w| w == "port");
    let source_port = port_idx
        .and_then(|i| parts.get(i + 1))
        .and_then(|s| s.parse().ok());

    (user, source_ip, source_port)
}

/// Extract the value of a `key=value` pair from a PAM log line.
///
/// The value ends at the next whitespace or `;` character.  The key must be
/// preceded by a word boundary (space, tab, `;`, or start of line) so that
/// e.g. searching for `user=` does not match inside `ruser=`.
fn extract_kv(line: &str, key: &str) -> Option<String> {
    let bytes = line.as_bytes();
    let key_bytes = key.as_bytes();
    let mut search_start = 0usize;

    loop {
        // Find the next occurrence of `key` starting from `search_start`.
        let rel = line[search_start..].find(key)?;
        let abs = search_start + rel;

        // Require a word boundary immediately before the key.
        let at_boundary = abs == 0
            || matches!(bytes.get(abs - 1), Some(&b' ') | Some(&b'\t') | Some(&b';'));

        if at_boundary {
            let rest = &line[abs + key.len()..];
            let value: String = rest
                .chars()
                .take_while(|&c| c != ' ' && c != '\t' && c != ';')
                .collect();
            return if value.is_empty() { None } else { Some(value) };
        }

        // Skip past this occurrence and try again.
        search_start = abs + key_bytes.len();
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // extract_service
    // -----------------------------------------------------------------------

    #[test]
    fn extract_service_with_pid() {
        let line = "Feb 21 10:00:00 host sshd[1234]: Accepted password for alice from 1.2.3.4 port 22 ssh2";
        assert_eq!(extract_service(line), "sshd");
    }

    #[test]
    fn extract_service_sudo_no_pid() {
        let line = "Feb 21 10:00:00 host sudo: alice : TTY=pts/0 ; COMMAND=/usr/bin/ls";
        assert_eq!(extract_service(line), "sudo");
    }

    #[test]
    fn extract_service_su_with_pid() {
        let line = "Feb 21 10:00:00 host su[999]: Successful su for bob by alice";
        assert_eq!(extract_service(line), "su");
    }

    // -----------------------------------------------------------------------
    // extract_message
    // -----------------------------------------------------------------------

    #[test]
    fn extract_message_with_pid() {
        let line = "Feb 21 10:00:00 host sshd[42]: hello world";
        assert_eq!(extract_message(line).as_deref(), Some("hello world"));
    }

    #[test]
    fn extract_message_without_pid() {
        let line = "Feb 21 10:00:00 host sudo: user ran something";
        assert_eq!(extract_message(line).as_deref(), Some("user ran something"));
    }

    // -----------------------------------------------------------------------
    // parse_user_from_ip_port
    // -----------------------------------------------------------------------

    #[test]
    fn parse_user_from_ip_port_full() {
        let (user, ip, port) = parse_user_from_ip_port("alice from 192.168.1.10 port 54321 ssh2");
        assert_eq!(user, "alice");
        assert_eq!(ip.as_deref(), Some("192.168.1.10"));
        assert_eq!(port, Some(54321u16));
    }

    #[test]
    fn parse_user_from_ip_port_no_port() {
        let (user, ip, port) = parse_user_from_ip_port("bob from 10.0.0.1");
        assert_eq!(user, "bob");
        assert_eq!(ip.as_deref(), Some("10.0.0.1"));
        assert_eq!(port, None);
    }

    #[test]
    fn parse_user_from_ip_port_only_user() {
        let (user, ip, port) = parse_user_from_ip_port("charlie");
        assert_eq!(user, "charlie");
        assert_eq!(ip, None);
        assert_eq!(port, None);
    }

    #[test]
    fn parse_user_from_ip_port_empty() {
        let (user, ip, port) = parse_user_from_ip_port("");
        assert_eq!(user, "unknown");
        assert_eq!(ip, None);
        assert_eq!(port, None);
    }

    // -----------------------------------------------------------------------
    // parse_auth_line — SSH accepted
    // -----------------------------------------------------------------------

    #[test]
    fn parse_ssh_accepted_password_success() {
        let line = "Feb 21 10:00:00 host sshd[1234]: Accepted password for alice from 192.168.1.10 port 54321 ssh2";
        let data = parse_auth_line(line).expect("should parse");
        assert_eq!(data.user, "alice");
        assert_eq!(data.source_ip.as_deref(), Some("192.168.1.10"));
        assert_eq!(data.source_port, Some(54321));
        assert_eq!(data.auth_method, "password");
        assert_eq!(data.status, "Success");
        assert_eq!(data.outcome, "Logon");
        assert_eq!(data.service, "sshd");
    }

    #[test]
    fn parse_ssh_accepted_publickey_success() {
        let line = "Feb 21 10:00:00 host sshd[1234]: Accepted publickey for bob from 10.0.0.5 port 22222 ssh2";
        let data = parse_auth_line(line).expect("should parse");
        assert_eq!(data.user, "bob");
        assert_eq!(data.auth_method, "publickey");
        assert_eq!(data.status, "Success");
        assert_eq!(data.outcome, "Logon");
    }

    // -----------------------------------------------------------------------
    // parse_auth_line — SSH failed
    // -----------------------------------------------------------------------

    #[test]
    fn parse_ssh_failed_password() {
        let line = "Feb 21 10:01:00 host sshd[1234]: Failed password for alice from 1.2.3.4 port 60000 ssh2";
        let data = parse_auth_line(line).expect("should parse");
        assert_eq!(data.user, "alice");
        assert_eq!(data.source_ip.as_deref(), Some("1.2.3.4"));
        assert_eq!(data.source_port, Some(60000));
        assert_eq!(data.auth_method, "password");
        assert_eq!(data.status, "Failure");
        assert_eq!(data.outcome, "Logon");
    }

    #[test]
    fn parse_ssh_failed_password_invalid_user() {
        // "invalid user" prefix is stripped so USER is still extracted.
        let line = "Feb 21 10:01:00 host sshd[1234]: Failed password for invalid user hacker from 5.5.5.5 port 11111 ssh2";
        let data = parse_auth_line(line).expect("should parse");
        assert_eq!(data.user, "hacker");
        assert_eq!(data.source_ip.as_deref(), Some("5.5.5.5"));
        assert_eq!(data.status, "Failure");
    }

    #[test]
    fn parse_ssh_failed_publickey() {
        let line = "Feb 21 10:01:00 host sshd[1234]: Failed publickey for root from 9.9.9.9 port 50000 ssh2";
        let data = parse_auth_line(line).expect("should parse");
        assert_eq!(data.user, "root");
        assert_eq!(data.auth_method, "publickey");
        assert_eq!(data.status, "Failure");
    }

    // -----------------------------------------------------------------------
    // parse_auth_line — invalid user
    // -----------------------------------------------------------------------

    #[test]
    fn parse_invalid_user_with_ip() {
        let line = "Feb 21 10:02:00 host sshd[555]: Invalid user ghost from 8.8.8.8 port 12345";
        let data = parse_auth_line(line).expect("should parse");
        assert_eq!(data.user, "ghost");
        assert_eq!(data.source_ip.as_deref(), Some("8.8.8.8"));
        assert_eq!(data.auth_method, "unknown");
        assert_eq!(data.status, "Failure");
        assert_eq!(data.outcome, "Logon");
    }

    #[test]
    fn parse_invalid_user_without_ip() {
        let line = "Feb 21 10:02:00 host sshd[555]: Invalid user nobody";
        let data = parse_auth_line(line).expect("should parse");
        assert_eq!(data.user, "nobody");
        assert_eq!(data.source_ip, None);
        assert_eq!(data.status, "Failure");
    }

    // -----------------------------------------------------------------------
    // parse_auth_line — sessions
    // -----------------------------------------------------------------------

    #[test]
    fn parse_session_opened_logon() {
        let line = "Feb 21 10:03:00 host sshd[777]: pam_unix(sshd:session): session opened for user alice by (uid=0)";
        let data = parse_auth_line(line).expect("should parse");
        assert_eq!(data.user, "alice");
        assert_eq!(data.auth_method, "session");
        assert_eq!(data.status, "Success");
        assert_eq!(data.outcome, "Logon");
    }

    #[test]
    fn parse_session_closed_logoff() {
        let line = "Feb 21 10:04:00 host sshd[777]: pam_unix(sshd:session): session closed for user alice";
        let data = parse_auth_line(line).expect("should parse");
        assert_eq!(data.user, "alice");
        assert_eq!(data.auth_method, "session");
        assert_eq!(data.status, "Success");
        assert_eq!(data.outcome, "Logoff");
    }

    // -----------------------------------------------------------------------
    // parse_auth_line — sudo
    // -----------------------------------------------------------------------

    #[test]
    fn parse_sudo_command_event() {
        let line = "Feb 21 10:05:00 host sudo[888]: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt-get update";
        let data = parse_auth_line(line).expect("should parse");
        assert_eq!(data.user, "alice");
        assert_eq!(data.auth_method, "sudo");
        assert_eq!(data.status, "Success");
        assert_eq!(data.outcome, "Logon");
        assert_eq!(data.service, "sudo");
    }

    #[test]
    fn parse_sudo_without_pid_brackets() {
        let line = "Feb 21 10:05:00 host sudo: bob : TTY=pts/1 ; PWD=/root ; USER=root ; COMMAND=/bin/bash";
        let data = parse_auth_line(line).expect("should parse");
        assert_eq!(data.user, "bob");
        assert_eq!(data.auth_method, "sudo");
    }

    // -----------------------------------------------------------------------
    // parse_auth_line — su
    // -----------------------------------------------------------------------

    #[test]
    fn parse_su_success_event() {
        let line = "Feb 21 10:06:00 host su[999]: Successful su for root by alice";
        let data = parse_auth_line(line).expect("should parse");
        assert_eq!(data.user, "root");
        assert_eq!(data.auth_method, "su");
        assert_eq!(data.status, "Success");
        assert_eq!(data.outcome, "Logon");
    }

    // -----------------------------------------------------------------------
    // parse_auth_line — PAM failure
    // -----------------------------------------------------------------------

    #[test]
    fn parse_pam_failure_with_user_and_rhost() {
        let line = "Feb 21 10:07:00 host sshd[2000]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.5  user=charlie";
        let data = parse_auth_line(line).expect("should parse");
        assert_eq!(data.user, "charlie");
        assert_eq!(data.source_ip.as_deref(), Some("203.0.113.5"));
        assert_eq!(data.auth_method, "pam");
        assert_eq!(data.status, "Failure");
        assert_eq!(data.outcome, "Logon");
    }

    #[test]
    fn parse_pam_failure_without_user() {
        let line = "Feb 21 10:07:00 host login[3000]: pam_unix(login:auth): authentication failure; logname=root uid=0";
        let data = parse_auth_line(line).expect("should parse");
        assert_eq!(data.user, "unknown");
        assert_eq!(data.auth_method, "pam");
        assert_eq!(data.status, "Failure");
    }

    // -----------------------------------------------------------------------
    // parse_auth_line — unrelated lines return None
    // -----------------------------------------------------------------------

    #[test]
    fn parse_unrelated_line_returns_none() {
        let line = "Feb 21 10:08:00 host systemd[1]: Started OpenSSH Daemon.";
        assert!(parse_auth_line(line).is_none());
    }

    #[test]
    fn parse_empty_line_returns_none() {
        assert!(parse_auth_line("").is_none());
    }

    #[test]
    fn parse_random_text_returns_none() {
        assert!(parse_auth_line("this is not a log line").is_none());
    }

    // -----------------------------------------------------------------------
    // classify_auth_severity
    // -----------------------------------------------------------------------

    fn make_auth_data(status: &str, auth_method: &str, outcome: &str) -> AuthenticationActivityData {
        AuthenticationActivityData {
            user: "testuser".into(),
            source_ip: None,
            source_port: None,
            auth_method: auth_method.into(),
            status: status.into(),
            outcome: outcome.into(),
            service: "sshd".into(),
        }
    }

    #[test]
    fn classify_severity_failure_is_medium() {
        let data = make_auth_data("Failure", "password", "Logon");
        assert_eq!(classify_auth_severity(&data), OcsfSeverity::Medium);
    }

    #[test]
    fn classify_severity_sudo_success_is_low() {
        let data = make_auth_data("Success", "sudo", "Logon");
        assert_eq!(classify_auth_severity(&data), OcsfSeverity::Low);
    }

    #[test]
    fn classify_severity_su_success_is_low() {
        let data = make_auth_data("Success", "su", "Logon");
        assert_eq!(classify_auth_severity(&data), OcsfSeverity::Low);
    }

    #[test]
    fn classify_severity_password_success_is_informational() {
        let data = make_auth_data("Success", "password", "Logon");
        assert_eq!(classify_auth_severity(&data), OcsfSeverity::Informational);
    }

    #[test]
    fn classify_severity_session_logon_is_informational() {
        let data = make_auth_data("Success", "session", "Logon");
        assert_eq!(classify_auth_severity(&data), OcsfSeverity::Informational);
    }

    // -----------------------------------------------------------------------
    // auth_activity
    // -----------------------------------------------------------------------

    #[test]
    fn auth_activity_logoff() {
        let data = make_auth_data("Success", "session", "Logoff");
        let (name, id) = auth_activity(&data);
        assert_eq!(name, "Logoff");
        assert_eq!(id, 2);
    }

    #[test]
    fn auth_activity_logon() {
        let data = make_auth_data("Success", "password", "Logon");
        let (name, id) = auth_activity(&data);
        assert_eq!(name, "Logon");
        assert_eq!(id, 1);
    }

    #[test]
    fn auth_activity_failure_is_logon() {
        let data = make_auth_data("Failure", "password", "Logon");
        let (name, id) = auth_activity(&data);
        assert_eq!(name, "Logon");
        assert_eq!(id, 1);
    }
}
