/** ATT&CK enterprise tactic names by ID, as the backend names them (engine/sigma_engine.py). */
const TACTIC_NAMES: Record<string, string> = {
  TA0043: 'Reconnaissance',
  TA0042: 'Resource Development',
  TA0001: 'Initial Access',
  TA0002: 'Execution',
  TA0003: 'Persistence',
  TA0004: 'Privilege Escalation',
  TA0005: 'Defense Evasion',
  TA0006: 'Credential Access',
  TA0007: 'Discovery',
  TA0008: 'Lateral Movement',
  TA0009: 'Collection',
  TA0011: 'Command and Control',
  TA0010: 'Exfiltration',
  TA0040: 'Impact',
}

/** Name of a tactic ID such as "TA0006"; an unknown value is returned unchanged. */
export function tacticName(id: string): string {
  return TACTIC_NAMES[id.toUpperCase()] ?? id
}
