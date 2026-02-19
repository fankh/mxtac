import { useState, useRef, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { TopBar } from '../../layout/TopBar'
import { apiClient } from '../../../lib/api'

interface Rule {
  id: string
  title: string
  level: string
  status: string
  enabled: boolean
  technique_ids: string[]
  tactic_ids: string[]
  hit_count: number
  fp_count: number
}

const LEVEL_COLOR: Record<string, string> = {
  critical: 'text-crit-text bg-[#FDECEA]',
  high:     'text-[#C45C00] bg-[#FEF3E2]',
  medium:   'text-[#5B5B00] bg-[#FEFBE8]',
  low:      'text-text-muted bg-[#F4F6F8]',
  informational: 'text-text-muted bg-[#F4F6F8]',
}

const REQUIRED_SIGMA_FIELDS = ['title', 'detection', 'logsource'] as const

async function fetchRules(): Promise<Rule[]> {
  const resp = await apiClient.get('/rules')
  return resp.data
}

// ── YAML validation helpers ─────────────────────────────────────────────────

/**
 * Lightweight YAML validation for Sigma rules.
 * Checks that the three mandatory top-level keys (title, detection, logsource)
 * are present.  We parse with a simple regex-based approach rather than pulling
 * in a full YAML library to keep the bundle lean.  A real YAML parse error on
 * the backend will still be caught by the API call.
 */
function validateSigmaYaml(yaml: string): string[] {
  const errors: string[] = []
  const trimmed = yaml.trim()

  if (!trimmed) {
    errors.push('YAML content is empty')
    return errors
  }

  // Parse top-level keys (lines that start at column 0 and contain a colon)
  const topLevelKeys = new Set<string>()
  for (const line of trimmed.split('\n')) {
    // Skip comments and blank lines
    if (/^\s*#/.test(line) || /^\s*$/.test(line)) continue
    const match = line.match(/^([a-zA-Z_][\w-]*)\s*:/)
    if (match) {
      topLevelKeys.add(match[1])
    }
  }

  for (const field of REQUIRED_SIGMA_FIELDS) {
    if (!topLevelKeys.has(field)) {
      errors.push(`Missing required field: "${field}"`)
    }
  }

  return errors
}

export function RulesPage() {
  const queryClient = useQueryClient()
  const fileInputRef = useRef<HTMLInputElement>(null)

  const [levelFilter, setLevelFilter] = useState<string | null>(null)
  const [enabledFilter, setEnabledFilter] = useState<boolean | null>(null)
  const [search, setSearch] = useState('')
  const [showEditor, setShowEditor] = useState(false)
  const [editorYaml, setEditorYaml] = useState(EXAMPLE_SIGMA)
  const [validationErrors, setValidationErrors] = useState<string[]>([])
  const [saveError, setSaveError] = useState<string | null>(null)

  const { data = [], isLoading, refetch } = useQuery({
    queryKey: ['rules'],
    queryFn: fetchRules,
  })

  // ── Save mutation ─────────────────────────────────────────────────────────

  const saveMutation = useMutation({
    mutationFn: async (yamlContent: string) => {
      // Extract the title from YAML for the API payload
      const titleMatch = yamlContent.match(/^title:\s*(.+)$/m)
      const title = titleMatch ? titleMatch[1].trim() : 'Untitled Rule'
      const resp = await apiClient.post('/rules', {
        title,
        content: yamlContent,
        enabled: true,
      })
      return resp.data
    },
    onSuccess: () => {
      setShowEditor(false)
      setEditorYaml(EXAMPLE_SIGMA)
      setValidationErrors([])
      setSaveError(null)
      queryClient.invalidateQueries({ queryKey: ['rules'] })
    },
    onError: (err: unknown) => {
      const msg =
        (err as { response?: { data?: { detail?: string } } })?.response?.data
          ?.detail ?? 'Failed to save rule'
      setSaveError(msg)
    },
  })

  // ── Handlers ──────────────────────────────────────────────────────────────

  const handleSave = useCallback(() => {
    setSaveError(null)
    const errors = validateSigmaYaml(editorYaml)
    setValidationErrors(errors)
    if (errors.length > 0) return
    saveMutation.mutate(editorYaml)
  }, [editorYaml, saveMutation])

  const handleFileImport = useCallback(() => {
    fileInputRef.current?.click()
  }, [])

  const handleFileChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0]
      if (!file) return
      const reader = new FileReader()
      reader.onload = (ev) => {
        const content = ev.target?.result
        if (typeof content === 'string') {
          setEditorYaml(content)
          setValidationErrors([])
          setSaveError(null)
          setShowEditor(true)
        }
      }
      reader.readAsText(file)
      // Reset so the same file can be re-imported
      e.target.value = ''
    },
    [],
  )

  const handleEditorClose = useCallback(() => {
    setShowEditor(false)
    setValidationErrors([])
    setSaveError(null)
  }, [])

  const visible = data.filter((r) => {
    if (levelFilter && r.level !== levelFilter) return false
    if (enabledFilter !== null && r.enabled !== enabledFilter) return false
    if (search && !r.title.toLowerCase().includes(search.toLowerCase())) return false
    return true
  })

  return (
    <>
      <TopBar crumb="Sigma Rules" />
      <div className="pt-[46px] px-5 pb-6">

        {/* Hidden file input for YAML import */}
        <input
          ref={fileInputRef}
          type="file"
          accept=".yml,.yaml"
          className="hidden"
          onChange={handleFileChange}
        />

        {/* Toolbar */}
        <div className="flex items-center gap-2 py-3 flex-wrap">
          {['critical', 'high', 'medium', 'low'].map((l) => (
            <button
              key={l}
              onClick={() => setLevelFilter(levelFilter === l ? null : l)}
              className={`px-3 h-[26px] rounded-[5px] text-[11px] font-medium border capitalize transition-colors ${
                levelFilter === l ? 'bg-blue text-white border-blue' : 'bg-surface border-border text-text-secondary hover:border-blue'
              }`}
            >
              {l}
            </button>
          ))}
          <div className="w-px h-[20px] bg-border mx-1" />
          <button
            onClick={() => setEnabledFilter(enabledFilter === true ? null : true)}
            className={`px-3 h-[26px] rounded-[5px] text-[11px] border transition-colors ${
              enabledFilter === true ? 'bg-blue text-white border-blue' : 'bg-surface border-border text-text-secondary'
            }`}
          >
            Enabled only
          </button>
          <input
            className="ml-auto h-[28px] px-3 text-[11px] border border-border rounded-md bg-surface text-text-primary placeholder-text-muted focus:outline-none focus:border-blue w-[220px]"
            placeholder="Search rules..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <button
            onClick={handleFileImport}
            className="h-[28px] px-4 border border-border text-[12px] text-text-secondary rounded-md hover:border-blue transition-colors"
          >
            Import YAML
          </button>
          <button
            onClick={() => { setEditorYaml(EXAMPLE_SIGMA); setShowEditor(true); setValidationErrors([]); setSaveError(null) }}
            className="h-[28px] px-4 bg-blue text-white text-[12px] rounded-md hover:opacity-90"
          >
            + New Rule
          </button>
        </div>

        {/* Stats */}
        <div className="text-[11px] text-text-muted mb-2">
          {visible.length} of {data.length} rules
        </div>

        {/* Table */}
        <div className="bg-surface rounded-md shadow-card overflow-hidden">
          <div className="grid grid-cols-[1fr_70px_100px_80px_80px_80px_60px] gap-2 px-3 py-2 border-b border-border">
            {['Rule Title', 'Level', 'Techniques', 'Status', 'Hits', 'FP', 'Active'].map((h) => (
              <span key={h} className="text-[10px] font-medium text-text-muted uppercase">{h}</span>
            ))}
          </div>

          {isLoading && (
            <div className="flex items-center justify-center h-32 text-text-muted text-sm">Loading rules...</div>
          )}

          {!isLoading && visible.length === 0 && (
            <div className="flex flex-col items-center justify-center h-32 gap-2 text-text-muted text-sm">
              <div>No rules loaded</div>
              <button onClick={() => setShowEditor(true)} className="text-blue text-[11px] hover:underline">
                Create your first rule
              </button>
            </div>
          )}

          {visible.map((rule) => (
            <div key={rule.id} className="grid grid-cols-[1fr_70px_100px_80px_80px_80px_60px] gap-2 px-3 py-[6px] border-b border-section items-center hover:bg-page">
              <div className="min-w-0">
                <div className="text-[11px] text-text-primary truncate font-medium">{rule.title}</div>
                <div className="text-[10px] text-text-muted">{rule.id}</div>
              </div>
              <span className={`text-[10px] font-medium px-2 py-[2px] rounded capitalize w-fit ${LEVEL_COLOR[rule.level] ?? 'text-text-muted'}`}>
                {rule.level}
              </span>
              <div className="flex flex-wrap gap-1">
                {rule.technique_ids.slice(0, 2).map((t) => (
                  <span key={t} className="text-[9px] text-text-secondary bg-page border border-border rounded px-1">{t}</span>
                ))}
                {rule.technique_ids.length > 2 && (
                  <span className="text-[9px] text-text-muted">+{rule.technique_ids.length - 2}</span>
                )}
              </div>
              <span className="text-[10px] text-text-muted capitalize">{rule.status}</span>
              <span className="text-[11px] text-text-primary">{rule.hit_count.toLocaleString()}</span>
              <span className="text-[11px] text-text-muted">{rule.fp_count}</span>
              <div className="flex items-center">
                <div className={`w-[6px] h-[6px] rounded-full ${rule.enabled ? 'bg-[#28A745]' : 'bg-border'}`} />
              </div>
            </div>
          ))}
        </div>

        {/* Editor modal */}
        {showEditor && (
          <div className="fixed inset-0 bg-black/20 z-50 flex items-center justify-center">
            <div className="bg-surface rounded-lg shadow-panel w-[680px] max-h-[80vh] flex flex-col">
              <div className="flex items-center justify-between px-5 py-3 border-b border-border">
                <h2 className="text-[13px] font-semibold text-text-primary">New Sigma Rule</h2>
                <div className="flex items-center gap-2">
                  <button
                    onClick={handleFileImport}
                    className="text-[11px] text-blue hover:underline"
                  >
                    Import file
                  </button>
                  <button onClick={handleEditorClose} className="text-text-muted text-lg">x</button>
                </div>
              </div>
              <div className="flex-1 overflow-auto p-4">
                <textarea
                  className={`w-full h-[400px] text-[11px] font-mono bg-page border rounded-md p-3 text-text-primary focus:outline-none resize-none ${
                    validationErrors.length > 0 ? 'border-[#E53935] focus:border-[#E53935]' : 'border-border focus:border-blue'
                  }`}
                  value={editorYaml}
                  onChange={(e) => {
                    setEditorYaml(e.target.value)
                    // Clear errors as user types
                    if (validationErrors.length > 0) setValidationErrors([])
                    if (saveError) setSaveError(null)
                  }}
                  spellCheck={false}
                />

                {/* Validation errors */}
                {validationErrors.length > 0 && (
                  <div className="mt-2 space-y-1">
                    {validationErrors.map((err, i) => (
                      <div key={i} className="text-[11px] text-[#E53935] flex items-center gap-1">
                        <span className="inline-block w-[14px] h-[14px] rounded-full bg-[#FDECEA] text-[#E53935] text-center text-[9px] leading-[14px] font-bold flex-shrink-0">!</span>
                        {err}
                      </div>
                    ))}
                  </div>
                )}

                {/* API error */}
                {saveError && (
                  <div className="mt-2 text-[11px] text-[#E53935] bg-[#FDECEA] rounded px-3 py-2">
                    {saveError}
                  </div>
                )}
              </div>
              <div className="flex items-center gap-2 px-5 py-3 border-t border-border">
                <button
                  className="flex-1 h-[30px] bg-blue text-white text-[12px] rounded-md hover:opacity-90 disabled:opacity-50"
                  onClick={handleSave}
                  disabled={saveMutation.isPending}
                >
                  {saveMutation.isPending ? 'Saving...' : 'Save Rule'}
                </button>
                <button
                  className="h-[30px] px-4 border border-border text-[12px] text-text-secondary rounded-md"
                  onClick={handleEditorClose}
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </>
  )
}

const EXAMPLE_SIGMA = `title: Suspicious LSASS Memory Access
id:
status: experimental
description: Detects attempts to dump credentials from LSASS process memory
references:
  - https://attack.mitre.org/techniques/T1003/001/
author: MxTac
date: 2026/02/19
tags:
  - attack.credential_access
  - attack.t1003.001
logsource:
  category: process_access
  product: windows
detection:
  selection:
    TargetImage|endswith: '\\\\lsass.exe'
    GrantedAccess|contains:
      - '0x1010'
      - '0x1410'
      - '0x147a'
      - '0x1fffff'
  condition: selection
fields:
  - SourceImage
  - TargetImage
  - GrantedAccess
falsepositives:
  - Some AV products
level: high
`
