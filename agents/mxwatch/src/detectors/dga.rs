//! Domain Generation Algorithm (DGA) detection — feature 36.4.
//!
//! Identifies potential DGA-generated domains in DNS queries by combining
//! multiple heuristics into a single probability score (0.0–1.0):
//!
//! | Score       | Confidence | Action              |
//! |-------------|------------|---------------------|
//! | ≥ 0.7       | High       | Alert (High)        |
//! | 0.5 – 0.70  | Medium     | Alert (Medium)      |
//! | < 0.5       | Normal     | No alert            |
//!
//! **Heuristics (applied to the Second-Level Domain / SLD):**
//! 1. **Length** — SLDs > 15 chars are unusual for legitimate domains.
//! 2. **Numeric ratio** — high digit percentage is characteristic of DGAs.
//! 3. **Vowel ratio** — very low vowel content → non-pronounceable / machine-generated.
//! 4. **Consonant clusters** — long runs of consecutive consonants.
//! 5. **Pattern recognition** — hex-like (`[0-9a-f]`) and base32-like (`[a-z2-7]`)
//!    strings that match known DGA encoding schemes.
//! 6. **Bigram frequency** — ratio of low-frequency bigrams (unusual character pairs).
//!
//! **Whitelist:** known CDN/cloud domain fragments are skipped to reduce false
//! positives (Akamai, CloudFront, Fastly, Azure, Google, etc.).
//!
//! **MITRE ATT&CK:** T1568.002 — Dynamic Resolution: Domain Generation Algorithms.

use tracing::debug;

use crate::config::DgaDetectorConfig;
use crate::detectors::{Alert, AlertSeverity};
use crate::parsers::dns::DnsInfo;

// ---------------------------------------------------------------------------
// Static tables
// ---------------------------------------------------------------------------

/// Top-50 most frequent English bigrams (lowercase, alphabetical pairs only).
/// Source: Cornell/Oxford frequency analysis of large English corpora.
static COMMON_BIGRAMS: &[&str] = &[
    "th", "he", "in", "er", "an", "re", "on", "en", "at", "ou", "ed", "ha", "to", "or", "it",
    "is", "hi", "es", "ng", "et", "le", "nd", "of", "ti", "ly", "as", "al", "st", "nt", "ar",
    "se", "io", "ne", "ea", "ro", "li", "si", "ri", "me", "de", "co", "te", "ta", "om", "ch",
    "ca", "pe", "ma", "ot", "no",
];

/// English vowel set (lowercase).
const VOWELS: &[char] = &['a', 'e', 'i', 'o', 'u'];

/// CDN / cloud / major-platform domain substrings that should be whitelisted.
///
/// If the full queried domain name contains any of these substrings, the DGA
/// check is skipped.  This prevents false positives from legitimately
/// random-looking CDN hostnames (e.g. `d1rlqbwnfxb3kj.cloudfront.net`).
static WHITELIST: &[&str] = &[
    "akamai",
    "cloudfront",
    "fastly",
    "amazonaws",
    "azureedge",
    "cloudflare",
    "googleusercontent",
    "akadns",
    "edgekey",
    "edgesuite",
    "akamaihd",
    "akamaitechnologies",
    "cloudapp",
    "trafficmanager",
    "msecnd",
    "windows",
    "azure",
    "google",
    "apple",
    "microsoft",
    "amazon",
    "facebook",
    "twitter",
    "linkedin",
    "github",
    "netflix",
    "youtube",
    "instagram",
    "whatsapp",
    "shopify",
    "slack",
    "zoom",
    "dropbox",
    "cdn",
    "static",
];

// ---------------------------------------------------------------------------
// Detector
// ---------------------------------------------------------------------------

/// Stateless DGA domain detector.
///
/// Evaluates DNS query names against a suite of heuristics and returns an
/// [`Alert`] when the combined DGA probability score exceeds a configured
/// threshold.
pub struct DgaDetector {
    config: DgaDetectorConfig,
}

impl DgaDetector {
    pub fn new(config: &DgaDetectorConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }

    /// Evaluate a parsed DNS message for DGA-generated domains.
    ///
    /// Only outgoing queries (non-responses) are evaluated.  Returns the first
    /// alert triggered; callers may invoke again after consuming the alert to
    /// check remaining questions.
    pub fn evaluate(&self, dns: &DnsInfo) -> Option<Alert> {
        if !self.config.enabled {
            return None;
        }

        // Only analyse queries, not responses.
        if dns.is_response {
            return None;
        }

        for question in &dns.questions {
            let name = &question.name;

            // Extract the second-level domain (SLD) for analysis.
            let sld = extract_sld(name);

            // Skip SLDs that are too short to analyse reliably.
            if sld.len() < self.config.min_sld_length {
                debug!("DGA: skipping '{name}' — SLD '{sld}' is shorter than min ({} chars)", self.config.min_sld_length);
                continue;
            }

            // Whitelist: skip known CDN / cloud / major-platform domains.
            if is_whitelisted(name) {
                debug!("DGA: skipping whitelisted domain '{name}'");
                continue;
            }

            let score = self.compute_score(&sld);
            debug!(
                domain = name,
                sld = &sld,
                score = format!("{score:.3}"),
                "DGA heuristic score"
            );

            if score >= self.config.high_threshold {
                return Some(self.build_alert(name, &sld, score, AlertSeverity::High));
            } else if score >= self.config.medium_threshold {
                return Some(self.build_alert(name, &sld, score, AlertSeverity::Medium));
            }
        }

        None
    }

    /// Combine individual heuristic scores into a single DGA probability
    /// (0.0–1.0).  Individual components are summed and clamped.
    fn compute_score(&self, sld: &str) -> f64 {
        let s = sld.to_lowercase();
        if s.is_empty() {
            return 0.0;
        }

        let score = length_score(s.len())
            + numeric_ratio_score(&s)
            + vowel_score(&s)
            + consonant_cluster_score(&s)
            + pattern_score(&s)
            + bigram_score(&s);

        score.min(1.0).max(0.0)
    }

    fn build_alert(&self, domain: &str, sld: &str, score: f64, severity: AlertSeverity) -> Alert {
        let confidence = match severity {
            AlertSeverity::High => "high",
            _ => "medium",
        };
        // Round score to two decimal places for the evidence JSON.
        let score_rounded = (score * 100.0).round() / 100.0;
        Alert {
            detector: "dga".into(),
            severity,
            description: format!(
                "Possible DGA domain (T1568.002): '{domain}' scored {score_rounded:.2} ({confidence} confidence)"
            ),
            evidence: serde_json::json!({
                "domain": domain,
                "sld": sld,
                "dga_score": score_rounded,
                "technique_id": "T1568.002",
                "technique_name": "Dynamic Resolution: Domain Generation Algorithms",
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Individual heuristic scoring functions
// ---------------------------------------------------------------------------

/// Length score (max contribution: 0.35).
///
/// Unusually long second-level domains (> 15 chars) are a common DGA trait.
/// Most legitimate registrable domains are short and memorable.
fn length_score(len: usize) -> f64 {
    match len {
        0..=9 => 0.0,
        10..=15 => 0.05,
        16..=20 => 0.15,
        21..=30 => 0.25,
        _ => 0.35,
    }
}

/// Numeric ratio score (max contribution: 0.25).
///
/// DGAs frequently embed numeric seeds, counters, or encoded dates.  A high
/// proportion of digits in the SLD is suspicious.
fn numeric_ratio_score(s: &str) -> f64 {
    let digit_count = s.chars().filter(|c| c.is_ascii_digit()).count();
    let ratio = digit_count as f64 / s.len() as f64;
    if ratio > 0.5 {
        0.25
    } else if ratio > 0.3 {
        0.15
    } else if ratio > 0.1 {
        0.05
    } else {
        0.0
    }
}

/// Vowel ratio score (max contribution: 0.25).
///
/// Human-memorable domain names tend to have 25–45 % vowels (similar to
/// natural language).  Machine-generated strings often have very few vowels.
fn vowel_score(s: &str) -> f64 {
    let alpha_count = s.chars().filter(|c| c.is_ascii_alphabetic()).count();
    if alpha_count == 0 {
        // Entirely numeric or punctuated — very unusual for a legitimate SLD.
        return 0.25;
    }
    let vowel_count = s.chars().filter(|c| VOWELS.contains(c)).count();
    let vowel_ratio = vowel_count as f64 / alpha_count as f64;
    if vowel_ratio < 0.1 {
        0.25
    } else if vowel_ratio < 0.2 {
        0.15
    } else if vowel_ratio < 0.3 {
        0.05
    } else {
        0.0
    }
}

/// Consonant cluster score (max contribution: 0.20).
///
/// Legitimate domain names are generally pronounceable.  Long runs of
/// consecutive consonants (> 4) are a strong indicator of machine generation.
fn consonant_cluster_score(s: &str) -> f64 {
    let mut max_run = 0usize;
    let mut current_run = 0usize;
    for c in s.chars() {
        if c.is_ascii_alphabetic() && !VOWELS.contains(&c) {
            current_run += 1;
            if current_run > max_run {
                max_run = current_run;
            }
        } else {
            current_run = 0;
        }
    }
    if max_run > 6 {
        0.20
    } else if max_run > 4 {
        0.10
    } else {
        0.0
    }
}

/// Pattern score (max contribution: 0.40).
///
/// Many DGA families use deterministic encoding schemes:
/// - **Hex-like** (`[0-9a-f]+`, length > 8): matches MD5/SHA seed encoding.
/// - **Base32-like** (`[a-z2-7]+` with at least one `[2-7]` digit,
///   length > 10): matches base32-encoded payload DGAs.
fn pattern_score(s: &str) -> f64 {
    let len = s.len();
    if len < 6 {
        return 0.0;
    }

    // Hex-like: every character is in [0-9a-f] and the string is long enough
    // to exclude common short words that happen to use only those letters.
    if len > 8 && s.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')) {
        return 0.40;
    }

    // Base32-like: every character is in [a-z2-7] *and* at least one digit
    // [2-7] is present (pure alpha strings are handled by vowel/consonant
    // heuristics rather than the pattern heuristic).
    if len > 10
        && s.chars().all(|c| matches!(c, 'a'..='z' | '2'..='7'))
        && s.chars().any(|c| matches!(c, '2'..='7'))
    {
        return 0.30;
    }

    0.0
}

/// Bigram frequency score (max contribution: 0.20).
///
/// Natural language (and pronounceable domain names) contains a high
/// proportion of common English bigrams.  Randomly generated strings have
/// very few common bigrams.
fn bigram_score(s: &str) -> f64 {
    let chars: Vec<char> = s.chars().collect();
    let total_bigrams = chars.len().saturating_sub(1);
    if total_bigrams < 3 {
        return 0.0;
    }

    let mut common_count = 0usize;
    for i in 0..total_bigrams {
        if chars[i].is_ascii_alphabetic() && chars[i + 1].is_ascii_alphabetic() {
            let bigram = format!("{}{}", chars[i], chars[i + 1]);
            if COMMON_BIGRAMS.contains(&bigram.as_str()) {
                common_count += 1;
            }
        }
    }

    // Count only alphabetical bigrams as the denominator so that
    // digit-heavy strings don't artificially inflate the ratio.
    let alpha_bigrams = (0..total_bigrams)
        .filter(|&i| chars[i].is_ascii_alphabetic() && chars[i + 1].is_ascii_alphabetic())
        .count();

    if alpha_bigrams == 0 {
        // No alphabetical bigrams at all → very suspicious.
        return 0.20;
    }

    let common_ratio = common_count as f64 / alpha_bigrams as f64;
    if common_ratio < 0.1 {
        0.20
    } else if common_ratio < 0.2 {
        0.10
    } else {
        0.0
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Extract the Second-Level Domain (SLD) from a fully-qualified domain name.
///
/// | Input                  | Output      |
/// |------------------------|-------------|
/// | `foo.bar.example.com`  | `example`   |
/// | `example.com`          | `example`   |
/// | `localhost`            | `localhost`  |
fn extract_sld(name: &str) -> String {
    let trimmed = name.trim_end_matches('.');
    let labels: Vec<&str> = trimmed.split('.').collect();
    match labels.len() {
        0 => trimmed.to_string(),
        1 => labels[0].to_string(),
        _ => labels[labels.len() - 2].to_string(),
    }
}

/// Return `true` if the full domain name matches any known CDN / cloud / major
/// platform fragment, indicating the name is almost certainly legitimate.
fn is_whitelisted(domain: &str) -> bool {
    let lower = domain.to_lowercase();
    WHITELIST.iter().any(|entry| lower.contains(entry))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DgaDetectorConfig;
    use crate::parsers::dns::{DnsInfo, DnsQuestion};

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn make_detector() -> DgaDetector {
        DgaDetector::new(&DgaDetectorConfig::default())
    }

    fn make_query(name: &str) -> DnsInfo {
        DnsInfo {
            transaction_id: 1,
            is_response: false,
            opcode: 0,
            rcode: 0,
            questions: vec![DnsQuestion {
                name: name.to_string(),
                qtype: 1, // A
                qclass: 1,
            }],
            ..Default::default()
        }
    }

    // -----------------------------------------------------------------------
    // 1. Known DGA domain patterns → alerts expected
    // -----------------------------------------------------------------------

    #[test]
    fn test_hex_domain_high_confidence() {
        // "deadbeef12345678" is pure hex, 16 chars — classic DGA encoding.
        let det = make_detector();
        let dns = make_query("deadbeef12345678.com");
        let alert = det.evaluate(&dns);
        assert!(alert.is_some(), "hex DGA domain should trigger an alert");
        let alert = alert.unwrap();
        assert_eq!(alert.detector, "dga");
        assert_eq!(alert.severity, AlertSeverity::High);
    }

    #[test]
    fn test_all_consonants_high_confidence() {
        // "xkqbvzrmtpjnlwsg" — 17 chars, no vowels, all consonants.
        let det = make_detector();
        let dns = make_query("xkqbvzrmtpjnlwsg.com");
        let alert = det.evaluate(&dns);
        assert!(alert.is_some(), "all-consonant DGA domain should trigger");
        assert_eq!(alert.unwrap().severity, AlertSeverity::High);
    }

    #[test]
    fn test_high_numeric_ratio_domain() {
        // "j4k2m9p1q3r7s5t" — alternating consonants and digits, 0 vowels.
        let det = make_detector();
        let dns = make_query("j4k2m9p1q3r7s5t.com");
        let alert = det.evaluate(&dns);
        assert!(alert.is_some(), "high-numeric-ratio DGA domain should trigger");
        assert_eq!(alert.unwrap().severity, AlertSeverity::High);
    }

    #[test]
    fn test_base32_domain_high_confidence() {
        // "mfra2mzqgezdgnbv" — base32 charset [a-z2-7], 16 chars, contains '2'.
        let det = make_detector();
        let dns = make_query("mfra2mzqgezdgnbv.com");
        let alert = det.evaluate(&dns);
        assert!(alert.is_some(), "base32-like domain should trigger an alert");
    }

    // -----------------------------------------------------------------------
    // 2. Legitimate domains → no alerts expected
    // -----------------------------------------------------------------------

    #[test]
    fn test_normal_domain_no_alert() {
        let det = make_detector();
        assert!(det.evaluate(&make_query("api.github.com")).is_none());
    }

    #[test]
    fn test_short_common_domain_no_alert() {
        let det = make_detector();
        assert!(det.evaluate(&make_query("example.com")).is_none());
    }

    #[test]
    fn test_long_pronounceable_domain_no_alert() {
        // "stackoverflow" is 13 chars but highly pronounceable with normal bigrams.
        let det = make_detector();
        assert!(det.evaluate(&make_query("stackoverflow.com")).is_none());
    }

    #[test]
    fn test_mail_subdomain_no_alert() {
        let det = make_detector();
        assert!(det.evaluate(&make_query("mail.corp.example.com")).is_none());
    }

    // -----------------------------------------------------------------------
    // 3. DNS responses are not evaluated
    // -----------------------------------------------------------------------

    #[test]
    fn test_response_not_evaluated() {
        let det = make_detector();
        let dns = DnsInfo {
            is_response: true,
            questions: vec![DnsQuestion {
                name: "deadbeef12345678.com".to_string(),
                qtype: 1,
                qclass: 1,
            }],
            ..Default::default()
        };
        assert!(
            det.evaluate(&dns).is_none(),
            "DNS responses should not be evaluated for DGA"
        );
    }

    // -----------------------------------------------------------------------
    // 4. Whitelist suppresses alerts
    // -----------------------------------------------------------------------

    #[test]
    fn test_akamai_whitelisted() {
        let det = make_detector();
        let dns = make_query("a123bcd456.akamaiedge.net");
        assert!(det.evaluate(&dns).is_none(), "akamai domain should be whitelisted");
    }

    #[test]
    fn test_cloudfront_whitelisted() {
        let det = make_detector();
        let dns = make_query("d1rlqbwnfxb3kj.cloudfront.net");
        assert!(det.evaluate(&dns).is_none(), "cloudfront domain should be whitelisted");
    }

    #[test]
    fn test_github_whitelisted() {
        let det = make_detector();
        let dns = make_query("objects.githubusercontent.com");
        assert!(det.evaluate(&dns).is_none(), "github CDN should be whitelisted");
    }

    // -----------------------------------------------------------------------
    // 5. Disabled detector produces no alerts
    // -----------------------------------------------------------------------

    #[test]
    fn test_disabled_detector_no_alert() {
        let det = DgaDetector::new(&DgaDetectorConfig {
            enabled: false,
            ..Default::default()
        });
        let dns = make_query("deadbeef12345678.evil.com");
        assert!(det.evaluate(&dns).is_none(), "disabled detector must not alert");
    }

    // -----------------------------------------------------------------------
    // 6. Alert evidence fields
    // -----------------------------------------------------------------------

    #[test]
    fn test_alert_technique_id() {
        let det = make_detector();
        let alert = det.evaluate(&make_query("deadbeef12345678.evil.com")).expect("expected alert");
        assert_eq!(alert.evidence["technique_id"], "T1568.002");
        assert_eq!(
            alert.evidence["technique_name"],
            "Dynamic Resolution: Domain Generation Algorithms"
        );
    }

    #[test]
    fn test_alert_domain_and_sld() {
        let det = make_detector();
        let alert = det.evaluate(&make_query("deadbeef12345678.evil.com")).expect("expected alert");
        assert_eq!(alert.evidence["domain"], "deadbeef12345678.evil.com");
        assert_eq!(alert.evidence["sld"], "evil");
    }

    #[test]
    fn test_alert_dga_score_present() {
        let det = make_detector();
        let alert = det.evaluate(&make_query("deadbeef12345678.evil.com")).expect("expected alert");
        let score = alert.evidence["dga_score"].as_f64().expect("dga_score must be a number");
        assert!(score >= 0.7, "high-confidence DGA score should be ≥ 0.7, got {score}");
    }

    // -----------------------------------------------------------------------
    // 7. Short SLD is skipped
    // -----------------------------------------------------------------------

    #[test]
    fn test_short_sld_skipped() {
        let det = make_detector();
        // SLD = "ab" (2 chars) → below min_sld_length default (6).
        let dns = make_query("ab.com");
        assert!(det.evaluate(&dns).is_none(), "SLD shorter than minimum should be skipped");
    }

    #[test]
    fn test_empty_questions_no_alert() {
        let det = make_detector();
        let dns = DnsInfo {
            questions: vec![],
            ..Default::default()
        };
        assert!(det.evaluate(&dns).is_none());
    }

    // -----------------------------------------------------------------------
    // 8. Individual scoring functions
    // -----------------------------------------------------------------------

    #[test]
    fn test_length_score_boundaries() {
        assert_eq!(length_score(5), 0.0, "< 10 chars → 0.0");
        assert_eq!(length_score(9), 0.0, "9 chars → 0.0");
        assert_eq!(length_score(10), 0.05, "10 chars → 0.05");
        assert_eq!(length_score(15), 0.05, "15 chars → 0.05");
        assert_eq!(length_score(16), 0.15, "16 chars → 0.15");
        assert_eq!(length_score(20), 0.15, "20 chars → 0.15");
        assert_eq!(length_score(21), 0.25, "21 chars → 0.25");
        assert_eq!(length_score(30), 0.25, "30 chars → 0.25");
        assert_eq!(length_score(31), 0.35, "> 30 chars → 0.35");
    }

    #[test]
    fn test_numeric_ratio_score() {
        // "11111111" — 100 % digits → 0.25
        assert_eq!(numeric_ratio_score("11111111"), 0.25);
        // "a1b2c3d4e5" — 50 % digits → 0.15 (> 0.3)
        assert_eq!(numeric_ratio_score("a1b2c3d4e5"), 0.15);
        // "abc1def" — 1/7 ≈ 14 % digits → 0.05 (> 0.1)
        assert_eq!(numeric_ratio_score("abc1def"), 0.05);
        // "abcdef" — 0 digits → 0.0
        assert_eq!(numeric_ratio_score("abcdef"), 0.0);
    }

    #[test]
    fn test_vowel_score_no_vowels() {
        // All consonants → vowel_ratio = 0.0 → 0.25
        assert_eq!(vowel_score("bcdfrghj"), 0.25);
    }

    #[test]
    fn test_vowel_score_normal_english() {
        // "google" → vowels = o, o, e → 3/6 = 0.5 → 0.0
        assert_eq!(vowel_score("google"), 0.0);
    }

    #[test]
    fn test_vowel_score_all_digits() {
        // No alphabetic chars at all → 0.25
        assert_eq!(vowel_score("12345678"), 0.25);
    }

    #[test]
    fn test_consonant_cluster_score() {
        // 8 consecutive consonants → 0.20
        assert_eq!(consonant_cluster_score("xkqbvzrm"), 0.20);
        // 6 consecutive → 0.20 (> 6 threshold is >6, so 6 is not >6...)
        // Wait: the code says `if max_run > 6 { 0.20 } else if max_run > 4 { 0.10 }`
        // "strpls" = s,t,r,p,l,s = 6 consonants → max_run = 6, not > 6, so > 4 → 0.10
        assert_eq!(consonant_cluster_score("strpls"), 0.10);
        // 3 consecutive → 0.0
        assert_eq!(consonant_cluster_score("bcd"), 0.0);
        // Vowel breaks the run: "staeth" → "st"(2), "th"(2) → max = 2 → 0.0
        assert_eq!(consonant_cluster_score("staeth"), 0.0);
    }

    #[test]
    fn test_pattern_score_hex() {
        // Pure hex, > 8 chars → 0.40
        assert_eq!(pattern_score("deadbeef12345678"), 0.40);
        // Short hex (≤ 8 chars) → 0.0
        assert_eq!(pattern_score("deadbee"), 0.0);
        // Non-hex chars → 0.0
        assert_eq!(pattern_score("googleplex"), 0.0);
    }

    #[test]
    fn test_pattern_score_base32() {
        // "mfra2mzqgezdgnbv" — all [a-z2-7], > 10 chars, contains '2' → 0.30
        assert_eq!(pattern_score("mfra2mzqgezdgnbv"), 0.30);
        // All letters, no [2-7] → does not meet base32 criterion → 0.0
        assert_eq!(pattern_score("xkqbvzrmtpjnlwsg"), 0.0);
    }

    #[test]
    fn test_bigram_score_random() {
        // "xkqfzm" → no common English bigrams → 0.20
        assert_eq!(bigram_score("xkqfzm"), 0.20);
    }

    #[test]
    fn test_bigram_score_common_english() {
        // "the" → "th", "he" both common → ratio = 2/2 = 1.0 → 0.0
        assert_eq!(bigram_score("the"), 0.0);
    }

    // -----------------------------------------------------------------------
    // 9. extract_sld helper
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_sld_multi_label() {
        assert_eq!(extract_sld("foo.bar.example.com"), "example");
        assert_eq!(extract_sld("api.github.com"), "github");
    }

    #[test]
    fn test_extract_sld_two_labels() {
        assert_eq!(extract_sld("example.com"), "example");
        assert_eq!(extract_sld("evil.org"), "evil");
    }

    #[test]
    fn test_extract_sld_single_label() {
        assert_eq!(extract_sld("localhost"), "localhost");
    }

    #[test]
    fn test_extract_sld_trailing_dot() {
        // FQDN with trailing dot (common in DNS wire format).
        assert_eq!(extract_sld("example.com."), "example");
    }

    // -----------------------------------------------------------------------
    // 10. is_whitelisted helper
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_whitelisted_positive() {
        assert!(is_whitelisted("abc.akamaiedge.net"));
        assert!(is_whitelisted("x.cloudfront.net"));
        assert!(is_whitelisted("objects.githubusercontent.com"));
    }

    #[test]
    fn test_is_whitelisted_negative() {
        assert!(!is_whitelisted("evil.com"));
        assert!(!is_whitelisted("random123abc.net"));
    }
}
