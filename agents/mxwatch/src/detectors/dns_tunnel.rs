//! DNS tunneling detector.
//!
//! Identifies potential DNS tunneling by looking for:
//!   - Unusually long domain names
//!   - High Shannon entropy in labels
//!   - Excessive subdomain depth
//!   - Suspicious TXT / NULL record queries

use std::collections::HashMap;

use tracing::debug;

use crate::config::DnsTunnelDetectorConfig;
use crate::detectors::{Alert, AlertSeverity};
use crate::parsers::dns::DnsInfo;

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
    pub fn evaluate(&mut self, dns: &DnsInfo) -> Option<Alert> {
        for question in &dns.questions {
            let name = &question.name;

            // 1. Length check.
            if name.len() > self.config.max_label_length {
                debug!("DNS tunnel indicator: name too long ({})", name.len());
                return Some(self.build_alert(
                    name,
                    "Domain name exceeds maximum length threshold",
                    AlertSeverity::High,
                ));
            }

            // 2. Entropy check on the leftmost label (subdomain).
            if let Some(subdomain) = name.split('.').next() {
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

            // 3. Excessive label count.
            let label_count = name.matches('.').count() + 1;
            if label_count > 10 {
                debug!("DNS tunnel indicator: excessive labels ({label_count}) in '{name}'");
                return Some(self.build_alert(
                    name,
                    "Excessive subdomain depth",
                    AlertSeverity::Medium,
                ));
            }

            // 4. Track volume per base domain.
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

            // 5. TXT record queries are commonly used for tunneling.
            if question.qtype == 16 {
                debug!("DNS tunnel indicator: TXT query for '{name}'");
                // Not necessarily malicious, so lower severity.
                return Some(self.build_alert(
                    name,
                    "TXT record query (commonly used for tunneling)",
                    AlertSeverity::Low,
                ));
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
    // Length threshold
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
    // Entropy threshold
    // -----------------------------------------------------------------------

    #[test]
    fn test_high_entropy_subdomain_triggers_alert() {
        let mut det = make_detector();
        // A subdomain with 27 unique characters → entropy = log2(27) ≈ 4.75 > 4.5.
        // Domain names may contain a-z, A-Z, 0-9, so use a diverse mix.
        let dns = make_dns_info("aBcDeFgHiJkLmNoPqRsTuVwXyZ0.example.com", 1);
        let alert = det.evaluate(&dns);
        assert!(alert.is_some(), "expected alert for high-entropy subdomain");
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
    // Label count
    // -----------------------------------------------------------------------

    #[test]
    fn test_excessive_label_count_triggers_alert() {
        let mut det = make_detector();
        // 12 labels (dots) — more than 10.
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
    // TXT record (qtype=16)
    // -----------------------------------------------------------------------

    #[test]
    fn test_txt_record_triggers_low_severity_alert() {
        let mut det = make_detector();
        // TXT record queries are suspicious (commonly used for tunneling).
        let dns = make_dns_info("example.com", 16 /* TXT */);
        let alert = det.evaluate(&dns);
        assert!(alert.is_some(), "expected alert for TXT query");
        let alert = alert.unwrap();
        assert_eq!(alert.severity, AlertSeverity::Low);
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
}
