//! DNS tunneling detector — feature 25.9.
//!
//! Identifies potential DNS tunneling by looking for:
//!   - Unusually long total domain names
//!   - Unusually long individual labels (subdomains)
//!   - High Shannon entropy in the leftmost label
//!   - High Shannon entropy across all non-TLD labels combined
//!   - Excessive subdomain depth
//!   - Suspicious TXT / NULL / ANY record queries
//!   - Burst of queries to the same base domain

use std::collections::HashMap;

use tracing::debug;

use crate::config::DnsTunnelDetectorConfig;
use crate::detectors::{Alert, AlertSeverity};
use crate::parsers::dns::DnsInfo;

/// DNS record type NULL (RFC 1035) — used by dnscat2 and other tunneling tools.
const DNS_TYPE_NULL: u16 = 10;
/// DNS record type ANY — sometimes used for data exfiltration over DNS.
const DNS_TYPE_ANY: u16 = 255;
/// DNS record type TXT — the most common tunneling vehicle.
const DNS_TYPE_TXT: u16 = 16;

/// Maximum reasonable individual label length in chars.  RFC 1035 allows up
/// to 63 octets per label; labels longer than this threshold but still ≤ 63
/// are a strong indicator of encoded exfiltration data.
const MAX_INDIVIDUAL_LABEL_LEN: usize = 40;

/// Stateful DNS tunneling detector.
pub struct DnsTunnelDetector {
    config: DnsTunnelDetectorConfig,
    /// Track query volume per base domain to detect bursts.
    domain_counters: HashMap<String, usize>,
}

impl DnsTunnelDetector {
    pub fn new(config: &DnsTunnelDetectorConfig) -> Self {
        Self {
            config: config.clone(),
            domain_counters: HashMap::new(),
        }
    }

    /// Evaluate a DNS query for tunneling indicators.
    ///
    /// Returns the first alert triggered by any indicator.  Checks are
    /// ordered by severity: the most conclusive indicators fire first.
    pub fn evaluate(&mut self, dns: &DnsInfo) -> Option<Alert> {
        for question in &dns.questions {
            let name = &question.name;

            // 1. Total name length check.
            if name.len() > self.config.max_label_length {
                debug!("DNS tunnel indicator: name too long ({})", name.len());
                return Some(self.build_alert(
                    name,
                    "Domain name exceeds maximum length threshold",
                    AlertSeverity::High,
                ));
            }

            let labels: Vec<&str> = name.split('.').collect();

            // 2. Individual label length check.
            //    RFC 1035 limits labels to 63 octets; labels > 40 chars in
            //    real hostnames are extremely rare and suggest encoded data.
            for label in &labels {
                if label.len() > MAX_INDIVIDUAL_LABEL_LEN {
                    debug!(
                        "DNS tunnel indicator: label too long ({}) in '{}'",
                        label.len(),
                        name
                    );
                    return Some(self.build_alert(
                        name,
                        &format!(
                            "Individual label length ({}) exceeds threshold ({MAX_INDIVIDUAL_LABEL_LEN})",
                            label.len()
                        ),
                        AlertSeverity::High,
                    ));
                }
            }

            // 3. Entropy check on the leftmost label (primary subdomain).
            //    Encoded data (base32/base64/hex) produces high Shannon entropy.
            if let Some(subdomain) = labels.first() {
                let ent = crate::parsers::dns::entropy(subdomain);
                if subdomain.len() > 10 && ent > self.config.entropy_threshold {
                    debug!(
                        "DNS tunnel indicator: high entropy ({:.2}) in subdomain '{}'",
                        ent, subdomain
                    );
                    return Some(self.build_alert(
                        name,
                        &format!(
                            "High entropy ({ent:.2}) in subdomain suggests encoded data"
                        ),
                        AlertSeverity::High,
                    ));
                }
            }

            // 4. Combined entropy across all non-TLD labels.
            //    Tunneling tools that split payloads across multiple labels
            //    (e.g. "abc.def.ghi.attacker.com") may have moderate per-label
            //    entropy but high combined entropy.  Exclude the last two labels
            //    (effective TLD + registrable domain) from the combined string.
            if labels.len() > 3 {
                let payload_labels = &labels[..labels.len().saturating_sub(2)];
                let combined: String = payload_labels.join("");
                if combined.len() > 20 {
                    let combined_ent = crate::parsers::dns::entropy(&combined);
                    if combined_ent > self.config.entropy_threshold {
                        debug!(
                            "DNS tunnel indicator: high combined label entropy ({:.2}) in '{}'",
                            combined_ent, name
                        );
                        return Some(self.build_alert(
                            name,
                            &format!(
                                "High combined label entropy ({combined_ent:.2}) suggests split encoded data"
                            ),
                            AlertSeverity::Medium,
                        ));
                    }
                }
            }

            // 5. Excessive label count.
            let label_count = labels.len();
            if label_count > 10 {
                debug!("DNS tunnel indicator: excessive labels ({label_count}) in '{name}'");
                return Some(self.build_alert(
                    name,
                    "Excessive subdomain depth",
                    AlertSeverity::Medium,
                ));
            }

            // 6. Track volume per base domain.
            let base = extract_base_domain(name);
            let counter = self.domain_counters.entry(base.clone()).or_insert(0);
            *counter += 1;
            if *counter > 100 {
                // Reset to prevent unbounded growth; alert once per burst.
                *counter = 0;
                return Some(self.build_alert(
                    name,
                    &format!("Burst of >100 queries to base domain '{base}'"),
                    AlertSeverity::Medium,
                ));
            }

            // 7. Suspicious record type queries.
            match question.qtype {
                // TXT records are the most common tunneling vehicle.
                DNS_TYPE_TXT => {
                    debug!("DNS tunnel indicator: TXT query for '{name}'");
                    return Some(self.build_alert(
                        name,
                        "TXT record query (commonly used for tunneling)",
                        AlertSeverity::Low,
                    ));
                }
                // NULL records are used by dnscat2 and similar tools.
                DNS_TYPE_NULL => {
                    debug!("DNS tunnel indicator: NULL query for '{name}'");
                    return Some(self.build_alert(
                        name,
                        "NULL record query (used by dnscat2 and similar tunneling tools)",
                        AlertSeverity::Medium,
                    ));
                }
                // ANY queries can be used to maximise response size for exfiltration.
                DNS_TYPE_ANY => {
                    debug!("DNS tunnel indicator: ANY query for '{name}'");
                    return Some(self.build_alert(
                        name,
                        "ANY record query (can be used to amplify DNS responses for exfiltration)",
                        AlertSeverity::Low,
                    ));
                }
                _ => {}
            }
        }

        None
    }

    fn build_alert(&self, domain: &str, reason: &str, severity: AlertSeverity) -> Alert {
        Alert {
            detector: "dns_tunnel".into(),
            severity,
            description: format!("Possible DNS tunneling: {reason}"),
            evidence: serde_json::json!({
                "domain": domain,
                "reason": reason,
            }),
        }
    }

    /// Periodic cleanup of stale counters.
    pub fn reset_counters(&mut self) {
        self.domain_counters.clear();
    }
}

/// Extract the effective base domain (last two labels).
fn extract_base_domain(name: &str) -> String {
    let labels: Vec<&str> = name.split('.').collect();
    if labels.len() <= 2 {
        name.to_string()
    } else {
        labels[labels.len() - 2..].join(".")
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DnsTunnelDetectorConfig;
    use crate::detectors::AlertSeverity;
    use crate::parsers::dns::{DnsInfo, DnsQuestion};

    fn make_detector() -> DnsTunnelDetector {
        DnsTunnelDetector::new(&DnsTunnelDetectorConfig {
            enabled: true,
            entropy_threshold: 4.5,
            max_label_length: 100,
        })
    }

    fn make_dns_info(name: &str, qtype: u16) -> DnsInfo {
        DnsInfo {
            transaction_id: 0x1234,
            is_response: false,
            opcode: 0,
            rcode: 0,
            questions: vec![DnsQuestion {
                name: name.to_string(),
                qtype,
                qclass: 1,
            }],
            ..Default::default()
        }
    }

    // -----------------------------------------------------------------------
    // 1. Total name length threshold
    // -----------------------------------------------------------------------

    #[test]
    fn test_long_domain_triggers_alert() {
        let mut det = make_detector();
        // A domain name > 100 chars should fire immediately.
        let long_name = format!("{}.example.com", "a".repeat(200));
        let dns = make_dns_info(&long_name, 1 /* A */);
        let alert = det.evaluate(&dns);
        assert!(alert.is_some(), "expected alert for long domain");
        let alert = alert.unwrap();
        assert_eq!(alert.detector, "dns_tunnel");
        assert_eq!(alert.severity, AlertSeverity::High);
    }

    // -----------------------------------------------------------------------
    // 2. Individual label length threshold
    // -----------------------------------------------------------------------

    #[test]
    fn test_long_individual_label_triggers_alert() {
        let mut det = make_detector();
        // A single label > 40 chars should trigger even if total < 100.
        let long_label = "a".repeat(41);
        let name = format!("{long_label}.example.com");
        let dns = make_dns_info(&name, 1);
        let alert = det.evaluate(&dns);
        assert!(alert.is_some(), "expected alert for long individual label");
        let alert = alert.unwrap();
        assert_eq!(alert.severity, AlertSeverity::High);
        assert!(alert.description.contains("label length"));
    }

    #[test]
    fn test_label_at_threshold_no_alert() {
        let mut det = make_detector();
        // Exactly 40 chars: not suspicious.
        let label = "a".repeat(40);
        let name = format!("{label}.example.com");
        let dns = make_dns_info(&name, 1);
        let alert = det.evaluate(&dns);
        assert!(alert.is_none(), "unexpected alert for label at threshold");
    }

    // -----------------------------------------------------------------------
    // 3. Leftmost label entropy
    // -----------------------------------------------------------------------

    #[test]
    fn test_high_entropy_subdomain_triggers_alert() {
        let mut det = make_detector();
        // A subdomain with 27 unique characters → entropy = log2(27) ≈ 4.75 > 4.5.
        // Domain names may contain a-z, A-Z, 0-9, so use a diverse mix.
        let dns = make_dns_info("aBcDeFgHiJkLmNoPqRsTuVwXyZ0.example.com", 1);
        let alert = det.evaluate(&dns);
        assert!(alert.is_some(), "expected alert for high-entropy subdomain");
        let alert = alert.unwrap();
        assert_eq!(alert.severity, AlertSeverity::High);
    }

    #[test]
    fn test_low_entropy_short_subdomain_no_alert() {
        let mut det = make_detector();
        // Short, low-entropy subdomain like "www".
        let dns = make_dns_info("www.example.com", 1);
        let alert = det.evaluate(&dns);
        assert!(alert.is_none(), "unexpected alert for normal domain");
    }

    // -----------------------------------------------------------------------
    // 4. Combined label entropy
    // -----------------------------------------------------------------------

    #[test]
    fn test_high_combined_entropy_across_labels_triggers_alert() {
        let mut det = make_detector();
        // Each label is 8 chars (≤10) so the leftmost-label entropy check won't
        // fire (requires len > 10), but combined payload labels exceed 20 chars
        // and have high Shannon entropy (24 unique chars in 24-char string →
        // entropy = log2(24) ≈ 4.58 bits > 4.5 threshold).
        //
        // "aBcDeF1g.hIjKlM2n.oP3qRsT4.attacker.com"
        //   combined payload labels: "aBcDeF1ghIjKlM2noP3qRsT4" (24 chars, all distinct)
        let dns = make_dns_info("aBcDeF1g.hIjKlM2n.oP3qRsT4.attacker.com", 1);
        let alert = det.evaluate(&dns);
        assert!(
            alert.is_some(),
            "expected alert for high combined label entropy"
        );
    }

    #[test]
    fn test_low_combined_entropy_no_alert() {
        let mut det = make_detector();
        // Repetitive labels produce low combined entropy.
        let dns = make_dns_info("aaa.bbb.ccc.example.com", 1);
        let alert = det.evaluate(&dns);
        // Should not trigger the combined-entropy check (and no other check fires).
        // Combined "aaabbbccc" has low entropy ≈ 1.58 bits < 4.5 threshold.
        assert!(alert.is_none(), "unexpected alert for low-entropy labels");
    }

    // -----------------------------------------------------------------------
    // 5. Label count
    // -----------------------------------------------------------------------

    #[test]
    fn test_excessive_label_count_triggers_alert() {
        let mut det = make_detector();
        // 13 labels — more than 10.
        let name = "a.b.c.d.e.f.g.h.i.j.k.example.com";
        let dns = make_dns_info(name, 1);
        let alert = det.evaluate(&dns);
        assert!(alert.is_some(), "expected alert for excessive labels");
        let alert = alert.unwrap();
        assert_eq!(alert.severity, AlertSeverity::Medium);
    }

    #[test]
    fn test_normal_label_count_no_alert() {
        let mut det = make_detector();
        // Normal 3-label domain.
        let dns = make_dns_info("mail.example.com", 1);
        let alert = det.evaluate(&dns);
        assert!(alert.is_none());
    }

    // -----------------------------------------------------------------------
    // 6. Volume burst
    // -----------------------------------------------------------------------

    #[test]
    fn test_burst_triggers_alert_after_100_queries() {
        let mut det = make_detector();
        // 100 unique subdomain queries to the same base domain.
        for i in 0..100 {
            let name = format!("sub{i}.example.com");
            let dns = make_dns_info(&name, 1);
            let alert = det.evaluate(&dns);
            assert!(alert.is_none(), "unexpected early alert at query {i}");
        }
        // The 101st query should trigger the burst alert.
        let dns = make_dns_info("sub100.example.com", 1);
        let alert = det.evaluate(&dns);
        assert!(alert.is_some(), "expected burst alert after 100 queries");
        assert_eq!(alert.unwrap().severity, AlertSeverity::Medium);
    }

    // -----------------------------------------------------------------------
    // 7a. TXT record (qtype=16)
    // -----------------------------------------------------------------------

    #[test]
    fn test_txt_record_triggers_low_severity_alert() {
        let mut det = make_detector();
        let dns = make_dns_info("example.com", DNS_TYPE_TXT);
        let alert = det.evaluate(&dns);
        assert!(alert.is_some(), "expected alert for TXT query");
        let alert = alert.unwrap();
        assert_eq!(alert.severity, AlertSeverity::Low);
        assert!(alert.description.contains("TXT"));
    }

    // -----------------------------------------------------------------------
    // 7b. NULL record (qtype=10)
    // -----------------------------------------------------------------------

    #[test]
    fn test_null_record_triggers_medium_severity_alert() {
        let mut det = make_detector();
        let dns = make_dns_info("example.com", DNS_TYPE_NULL);
        let alert = det.evaluate(&dns);
        assert!(alert.is_some(), "expected alert for NULL query");
        let alert = alert.unwrap();
        assert_eq!(alert.severity, AlertSeverity::Medium);
        assert!(alert.description.contains("NULL"));
    }

    // -----------------------------------------------------------------------
    // 7c. ANY record (qtype=255)
    // -----------------------------------------------------------------------

    #[test]
    fn test_any_record_triggers_low_severity_alert() {
        let mut det = make_detector();
        let dns = make_dns_info("example.com", DNS_TYPE_ANY);
        let alert = det.evaluate(&dns);
        assert!(alert.is_some(), "expected alert for ANY query");
        let alert = alert.unwrap();
        assert_eq!(alert.severity, AlertSeverity::Low);
        assert!(alert.description.contains("ANY"));
    }

    // -----------------------------------------------------------------------
    // Normal traffic — no alerts
    // -----------------------------------------------------------------------

    #[test]
    fn test_normal_a_query_no_alert() {
        let mut det = make_detector();
        let dns = make_dns_info("api.github.com", 1 /* A */);
        assert!(det.evaluate(&dns).is_none());
    }

    #[test]
    fn test_empty_questions_no_alert() {
        let mut det = make_detector();
        let dns = DnsInfo {
            transaction_id: 1,
            questions: vec![],
            ..Default::default()
        };
        assert!(det.evaluate(&dns).is_none());
    }

    #[test]
    fn test_normal_subdomain_no_alert() {
        let mut det = make_detector();
        // Typical enterprise subdomain: short, low entropy, few labels.
        let dns = make_dns_info("vpn.corp.example.com", 1);
        assert!(det.evaluate(&dns).is_none());
    }

    // -----------------------------------------------------------------------
    // extract_base_domain helper
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_base_domain_multi_label() {
        assert_eq!(extract_base_domain("sub.example.com"), "example.com");
        assert_eq!(extract_base_domain("a.b.c.example.com"), "example.com");
    }

    #[test]
    fn test_extract_base_domain_two_labels() {
        assert_eq!(extract_base_domain("example.com"), "example.com");
    }

    #[test]
    fn test_extract_base_domain_single_label() {
        assert_eq!(extract_base_domain("localhost"), "localhost");
    }

    // -----------------------------------------------------------------------
    // Alert fields
    // -----------------------------------------------------------------------

    #[test]
    fn test_alert_contains_domain_in_evidence() {
        let mut det = make_detector();
        let long_name = format!("{}.example.com", "x".repeat(200));
        let dns = make_dns_info(&long_name, 1);
        let alert = det.evaluate(&dns).unwrap();
        assert_eq!(alert.evidence["domain"], long_name.as_str());
        assert_eq!(alert.detector, "dns_tunnel");
    }

    #[test]
    fn test_reset_counters_clears_state() {
        let mut det = make_detector();
        // Fill up to 100 queries.
        for i in 0..100 {
            det.evaluate(&make_dns_info(&format!("s{i}.example.com"), 1));
        }
        // Reset — counter drops to 0.
        det.reset_counters();
        // Next 100 queries should not trigger a burst alert.
        for i in 0..100 {
            let alert = det.evaluate(&make_dns_info(&format!("r{i}.example.com"), 1));
            assert!(alert.is_none(), "unexpected alert after reset at query {i}");
        }
    }
}
