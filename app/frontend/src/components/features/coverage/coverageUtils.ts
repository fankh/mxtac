import type { NavigatorTechnique } from '@/types/api'

/** Roles the backend grants `detections:write` to, which PUT /coverage/target requires. */
export const TARGET_EDIT_ROLES = ['analyst', 'hunter', 'engineer', 'admin']

export const TREND_WINDOWS = [
  { value: '7', label: '7 days' },
  { value: '30', label: '30 days' },
  { value: '90', label: '90 days' },
]

const SOURCE_LABELS: Record<string, string> = {
  wazuh: 'Wazuh',
  zeek: 'Zeek',
  suricata: 'Suricata',
}

export function sourceLabel(source: string): string {
  return SOURCE_LABELS[source] ?? source
}

export function formatPct(value: number): string {
  return `${Number.isInteger(value) ? value : value.toFixed(1)}%`
}

export interface TechniqueGroup {
  /** Parent technique ID, for example T1059. */
  parent: string
  techniques: NavigatorTechnique[]
  /** Enabled rules across the group (a rule that covers two sub-techniques counts twice). */
  ruleCount: number
}

/** Group techniques under their parent ID (T1059.001 → T1059), sorted by ID. */
export function groupTechniques(techniques: NavigatorTechnique[]): TechniqueGroup[] {
  const byParent = new Map<string, NavigatorTechnique[]>()
  for (const t of techniques) {
    const parent = t.techniqueID.split('.')[0]
    const list = byParent.get(parent)
    if (list) list.push(t)
    else byParent.set(parent, [t])
  }
  return [...byParent.entries()]
    .map(([parent, list]) => ({
      parent,
      techniques: [...list].sort((a, b) => a.techniqueID.localeCompare(b.techniqueID)),
      ruleCount: list.reduce((sum, t) => sum + t.score, 0),
    }))
    .sort((a, b) => a.parent.localeCompare(b.parent))
}

/** MITRE ATT&CK page for a technique or sub-technique ID. */
export function attackUrl(techniqueId: string): string {
  return `https://attack.mitre.org/techniques/${techniqueId.trim().toUpperCase().replace('.', '/')}/`
}

/** Fill opacity (0.15 to 1) for a value on a 0..max scale; 0 for no value. */
export function heatOpacity(value: number, max: number): number {
  if (value <= 0 || max <= 0) return 0
  return Math.round((0.15 + Math.min(1, value / max) * 0.85) * 100) / 100
}

/** Sub-technique part of an ATT&CK name ("Parent: Sub" → "Sub"), for use under the parent's heading. */
export function shortTechniqueName(name: string | undefined): string {
  if (!name) return ''
  const separator = name.indexOf(': ')
  return separator === -1 ? name : name.slice(separator + 2)
}
