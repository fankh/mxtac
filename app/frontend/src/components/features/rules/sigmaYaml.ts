import { dump, load, YAMLException } from 'js-yaml'

export interface YamlProblem {
  message: string
  /** Zero-based position of a syntax error, when the parser reports one. */
  line?: number
  column?: number
}

export interface SigmaCheck {
  errors: string[]
  /** The rule title, when the YAML has one. */
  title?: string
  problem?: YamlProblem
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/** Syntax check only: returns the parser error, or null when the text parses. */
export function yamlSyntaxProblem(text: string): YamlProblem | null {
  try {
    load(text)
    return null
  } catch (e: unknown) {
    if (e instanceof YAMLException) {
      return { message: e.reason || e.message, line: e.mark?.line, column: e.mark?.column }
    }
    return { message: 'Invalid YAML' }
  }
}

/**
 * The same structural checks the backend runs in POST /rules/test before compiling:
 * valid YAML, a mapping, with `title` and a `detection` block that has a `condition`.
 */
export function checkSigmaYaml(text: string): SigmaCheck {
  if (!text.trim()) return { errors: ['The rule is empty'] }

  let doc: unknown
  try {
    doc = load(text)
  } catch (e: unknown) {
    const problem: YamlProblem = e instanceof YAMLException
      ? { message: e.reason || e.message, line: e.mark?.line, column: e.mark?.column }
      : { message: 'Invalid YAML' }
    const where = problem.line !== undefined ? ` (line ${problem.line + 1})` : ''
    return { errors: [`YAML syntax error${where}: ${problem.message}`], problem }
  }

  if (!isRecord(doc)) return { errors: ['The rule must be a YAML mapping'] }

  const errors: string[] = []
  const title = typeof doc.title === 'string' && doc.title.trim() ? doc.title.trim() : undefined
  if (!title) errors.push('Missing required field: title')
  if (!('detection' in doc)) {
    errors.push('Missing required field: detection')
  } else if (!isRecord(doc.detection)) {
    errors.push('detection must be a mapping')
  } else if (!('condition' in doc.detection)) {
    errors.push('The detection block is missing condition')
  }
  return { errors, title }
}

/** Re-serialise YAML with two-space indents. Returns the input unchanged when it does not parse. */
export function formatYaml(text: string): string {
  try {
    const parsed = load(text)
    if (parsed === undefined || parsed === null) return text
    return dump(parsed, { indent: 2, lineWidth: -1, noRefs: true })
  } catch {
    return text
  }
}

export type SampleEvent = { event: Record<string, unknown> } | { error: string }

/** Parse the sample event box: it must hold one JSON object. */
export function parseSampleEvent(text: string): SampleEvent {
  if (!text.trim()) return { error: 'Enter a sample event as a JSON object' }
  try {
    const parsed: unknown = JSON.parse(text)
    if (!isRecord(parsed)) return { error: 'The sample event must be a JSON object' }
    return { event: parsed }
  } catch {
    return { error: 'The sample event is not valid JSON' }
  }
}

export const EXAMPLE_SIGMA = `title: Suspicious LSASS memory access
status: experimental
description: Detects attempts to read credentials from LSASS process memory
tags:
  - attack.credential_access
  - attack.t1003.001
logsource:
  category: process_access
  product: windows
detection:
  selection:
    TargetImage|endswith: '\\lsass.exe'
    GrantedAccess|contains:
      - '0x1010'
      - '0x1410'
  condition: selection
falsepositives:
  - Some endpoint protection products
level: high
`

export const EXAMPLE_EVENT = JSON.stringify(
  { TargetImage: 'C:\\Windows\\System32\\lsass.exe', GrantedAccess: '0x1010', SourceImage: 'C:\\Temp\\tool.exe' },
  null,
  2,
)
