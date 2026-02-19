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
