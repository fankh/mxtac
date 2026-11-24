import { Network, Radio, ScrollText, ShieldCheck, Webhook, type LucideIcon } from 'lucide-react'
import type { ConnectorConfig, ConnectorType } from '@/types/api'

export interface ConfigField {
  key: string
  label: string
  kind: 'text' | 'password' | 'number' | 'boolean' | 'list'
  placeholder?: string
  required?: boolean
  help?: string
  /** Initial state of a boolean field when adding a source. */
  defaultOn?: boolean
}

export interface ConnectorTypeInfo {
  type: ConnectorType
  label: string
  description: string
  icon: LucideIcon
  fields: ConfigField[]
  /** The backend can start and stop this type at runtime. */
  canRun: boolean
  /** POST /connectors/{id}/test has a check for this type. */
  canTest: boolean
}

const POLL_INTERVAL: ConfigField = {
  key: 'poll_interval_seconds',
  label: 'Poll interval (seconds)',
  kind: 'number',
  placeholder: '60',
}

/** The connector types the backend accepts, with the config keys each one reads. */
export const CONNECTOR_TYPES: ConnectorTypeInfo[] = [
  {
    type: 'wazuh',
    label: 'Wazuh',
    description: 'Polls the Wazuh manager API for host alerts.',
    icon: ShieldCheck,
    canRun: true,
    canTest: true,
    fields: [
      { key: 'url', label: 'Manager API URL', kind: 'text', placeholder: 'https://wazuh.internal:55000', required: true },
      { key: 'username', label: 'Username', kind: 'text', placeholder: 'wazuh-wui', required: true },
      { key: 'password', label: 'Password', kind: 'password', required: true },
      { key: 'verify_ssl', label: 'Verify TLS certificate', kind: 'boolean', defaultOn: true },
      POLL_INTERVAL,
    ],
  },
  {
    type: 'zeek',
    label: 'Zeek',
    description: 'Tails Zeek network logs from a directory on the MxTac server.',
    icon: Network,
    canRun: true,
    canTest: true,
    fields: [
      { key: 'log_dir', label: 'Log directory', kind: 'text', placeholder: '/opt/zeek/logs/current' },
      {
        key: 'log_types', label: 'Log types', kind: 'list', placeholder: 'conn, dns, http, ssl, files',
        help: 'Comma-separated. Leave empty for all of conn, dns, http, ssl and files.',
      },
      POLL_INTERVAL,
    ],
  },
  {
    type: 'suricata',
    label: 'Suricata',
    description: 'Tails the Suricata EVE JSON file on the MxTac server.',
    icon: Radio,
    canRun: true,
    canTest: true,
    fields: [
      { key: 'eve_file', label: 'EVE JSON file', kind: 'text', placeholder: '/var/log/suricata/eve.json' },
      {
        key: 'event_types', label: 'Event types', kind: 'list', placeholder: 'alert, dns, http, tls',
        help: 'Comma-separated. Leave empty for alert, dns, http and tls.',
      },
      POLL_INTERVAL,
    ],
  },
  {
    type: 'syslog',
    label: 'Syslog',
    description: 'Listens for RFC 3164 and RFC 5424 syslog messages over UDP.',
    icon: ScrollText,
    canRun: true,
    canTest: false,
    fields: [
      { key: 'host', label: 'Bind address', kind: 'text', placeholder: '0.0.0.0' },
      { key: 'port', label: 'UDP port', kind: 'number', placeholder: '514' },
      { key: 'max_message_size', label: 'Maximum message size (bytes)', kind: 'number', placeholder: '65535' },
    ],
  },
  {
    type: 'generic',
    label: 'Generic webhook',
    description: 'Receives JSON events that your own tools send to POST /api/v1/ingest.',
    icon: Webhook,
    canRun: false,
    canTest: false,
    fields: [
      {
        key: 'webhook_token', label: 'Webhook token', kind: 'password', required: true,
        help: 'Senders pass this in the X-MxTac-Token header. It cannot be shown again after saving.',
      },
    ],
  },
]

export function connectorTypeInfo(type: string): ConnectorTypeInfo | undefined {
  return CONNECTOR_TYPES.find((t) => t.type === type)
}

export type FieldValues = Record<string, string | boolean>

/** Starting form values: booleans take their default, everything else is empty. */
export function initialValues(fields: ConfigField[]): FieldValues {
  const values: FieldValues = {}
  for (const f of fields) values[f.key] = f.kind === 'boolean' ? (f.defaultOn ?? false) : ''
  return values
}

/**
 * Turn form values into the `config` object the backend stores.
 * Empty fields are left out so the connector falls back to its default. When `only` is given
 * (editing), just those keys are sent and the backend keeps the rest.
 */
export function buildConfig(fields: ConfigField[], values: FieldValues, only?: ReadonlySet<string>): ConnectorConfig {
  const config: ConnectorConfig = {}
  for (const f of fields) {
    if (only && !only.has(f.key)) continue
    const raw = values[f.key]
    if (f.kind === 'boolean') {
      config[f.key] = raw === true
      continue
    }
    const text = typeof raw === 'string' ? raw.trim() : ''
    if (!text) continue
    if (f.kind === 'number') {
      const n = Number(text)
      if (Number.isFinite(n)) config[f.key] = n
    } else if (f.kind === 'list') {
      const items = text.split(',').map((s) => s.trim()).filter(Boolean)
      if (items.length > 0) config[f.key] = items
    } else {
      config[f.key] = text
    }
  }
  return config
}

/** Labels of required fields that are still empty. */
export function missingRequired(fields: ConfigField[], values: FieldValues): string[] {
  return fields
    .filter((f) => f.required && f.kind !== 'boolean' && !String(values[f.key] ?? '').trim())
    .map((f) => f.label)
}

/** Labels of number fields whose text is not a whole number above zero. */
export function invalidNumbers(fields: ConfigField[], values: FieldValues): string[] {
  return fields
    .filter((f) => {
      if (f.kind !== 'number') return false
      const text = String(values[f.key] ?? '').trim()
      if (!text) return false
      const n = Number(text)
      return !Number.isInteger(n) || n <= 0
    })
    .map((f) => f.label)
}

/** Random token for a generic webhook source. */
export function generateToken(): string {
  const bytes = new Uint8Array(24)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

const STATUS: Record<string, { cls: string; label: string }> = {
  active: { cls: 'status-green', label: 'Active' },
  connecting: { cls: 'sev-medium', label: 'Connecting' },
  error: { cls: 'sev-critical', label: 'Error' },
  inactive: { cls: 'sev-info', label: 'Inactive' },
}

export function connectorStatus(status: string): { cls: string; label: string } {
  return STATUS[status] ?? { cls: 'sev-info', label: status || 'Unknown' }
}

export function formatLastSeen(value: string | null): string {
  if (!value) return 'Never'
  const d = new Date(value)
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString()
}
