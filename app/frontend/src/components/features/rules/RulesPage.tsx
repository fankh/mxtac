import { useState, useRef, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import Editor, { type OnMount } from '@monaco-editor/react'
import { load as yamlLoad, dump as yamlDump, YAMLException } from 'js-yaml'
import { TopBar } from '../../layout/TopBar'
import { apiClient } from '../../../lib/api'
import { useUIStore, type Theme } from '../../../stores/uiStore'

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

interface RuleDetail extends Rule {
  content: string
}

interface TestResult {
  matched: boolean
  errors: string[]
}

type IStandaloneCodeEditor = Parameters<OnMount>[0]
type Monaco = Parameters<OnMount>[1]

const LEVEL_COLOR: Record<string, string> = {
  critical: 'text-crit-text bg-crit-bg',
  high:     'text-high-text bg-high-bg',
  medium:   'text-warn-text bg-warn-bg',
  low:      'text-text-muted bg-page',
  informational: 'text-text-muted bg-page',
}

const REQUIRED_SIGMA_FIELDS = ['title', 'detection', 'logsource'] as const

async function fetchRules(): Promise<Rule[]> {
  const resp = await apiClient.get('/rules')
  return resp.data
}

// ── YAML helpers ─────────────────────────────────────────────────────────────

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

/** Map app theme to Monaco theme name. 'matrix' uses a custom theme registered via beforeMount. */
function getMonacoTheme(theme: Theme): string {
  if (theme === 'light') return 'vs'
  if (theme === 'matrix') return 'matrix'
  return 'vs-dark'
}

/** Re-serialize YAML through js-yaml for consistent formatting. Returns original on parse error. */
function formatYaml(yaml: string): string {
  try {
    const parsed = yamlLoad(yaml)
    return yamlDump(parsed, { indent: 2, lineWidth: -1, noRefs: true })
  } catch {
    return yaml
  }
}

export function RulesPage() {
  const queryClient = useQueryClient()
  const fileInputRef = useRef<HTMLInputElement>(null)
  const editorRef = useRef<IStandaloneCodeEditor | null>(null)
  const monacoRef = useRef<Monaco | null>(null)

  const theme = useUIStore((s) => s.theme)

  const [levelFilter, setLevelFilter] = useState<string | null>(null)
  const [enabledFilter, setEnabledFilter] = useState<boolean | null>(null)
  const [search, setSearch] = useState('')
  const [showEditor, setShowEditor] = useState(false)
  const [editorYaml, setEditorYaml] = useState(EXAMPLE_SIGMA)
  const [validationErrors, setValidationErrors] = useState<string[]>([])
  const [saveError, setSaveError] = useState<string | null>(null)
  const [testResult, setTestResult] = useState<TestResult | null>(null)
  // null = create mode, non-null = edit mode (holds the rule id being edited)
  const [editingRuleId, setEditingRuleId] = useState<string | null>(null)
  // tracks which row is loading so we can show a spinner on the row
  const [loadingRuleId, setLoadingRuleId] = useState<string | null>(null)

  const { data = [], isLoading } = useQuery({
    queryKey: ['rules'],
    queryFn: fetchRules,
  })

  // ── Save mutation ─────────────────────────────────────────────────────────

  const saveMutation = useMutation({
    mutationFn: async (yamlContent: string) => {
      if (editingRuleId) {
        // Edit mode: PATCH existing rule content
        const resp = await apiClient.patch(`/rules/${editingRuleId}`, { content: yamlContent })
        return resp.data
      }
      // Create mode: POST new rule
      const titleMatch = yamlContent.match(/^title:[ \t]*(.+)$/m)
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
      setEditingRuleId(null)
      setEditorYaml(EXAMPLE_SIGMA)
      setValidationErrors([])
      setSaveError(null)
      setTestResult(null)
      queryClient.invalidateQueries({ queryKey: ['rules'] })
    },
    onError: (err: unknown) => {
      const msg =
        (err as { response?: { data?: { detail?: string } } })?.response?.data
          ?.detail ?? 'Failed to save rule'
      setSaveError(msg)
    },
  })

  // ── Test mutation ──────────────────────────────────────────────────────────

  const testMutation = useMutation({
    mutationFn: async (yamlContent: string) => {
      const resp = await apiClient.post('/rules/test', {
        content: yamlContent,
        sample_event: {},
      })
      return resp.data as TestResult
    },
    onSuccess: (result) => {
      setTestResult(result)
    },
    onError: (err: unknown) => {
      const detail =
        (err as { response?: { data?: { detail?: string } } })?.response?.data
          ?.detail ?? 'Test failed'
      setTestResult({ matched: false, errors: [detail] })
    },
  })

  // ── Handlers ──────────────────────────────────────────────────────────────

  // Register custom Monaco themes before the editor mounts so they can be referenced by name.
  const handleBeforeMount = useCallback((monaco: Monaco) => {
    monaco.editor.defineTheme('matrix', {
      base: 'vs-dark',
      inherit: true,
      rules: [
        { token: '',         foreground: '00FF41' },
        { token: 'comment',  foreground: '005515' },
        { token: 'string',   foreground: '33FF57' },
        { token: 'keyword',  foreground: '00FF41', fontStyle: 'bold' },
        { token: 'number',   foreground: '00CC33' },
        { token: 'operator', foreground: '00BB30' },
      ],
      colors: {
        'editor.background':                '#0A0A0A',
        'editor.foreground':                '#00FF41',
        'editorLineNumber.foreground':      '#005515',
        'editorLineNumber.activeForeground':'#00FF41',
        'editor.selectionBackground':       '#003311',
        'editor.lineHighlightBackground':   '#0D1A0D',
        'editorCursor.foreground':          '#00FF41',
        'editor.inactiveSelectionBackground':'#002208',
        'editorBracketMatch.background':    '#003311',
        'editorBracketMatch.border':        '#00FF41',
      },
    })
  }, [])

  const handleEditorMount: OnMount = useCallback((editor, monaco) => {
    editorRef.current = editor
    monacoRef.current = monaco
  }, [])

  const handleEditorChange = (value: string | undefined) => {
    const yaml = value ?? ''
    setEditorYaml(yaml)
    if (validationErrors.length > 0) setValidationErrors([])
    if (saveError) setSaveError(null)
    if (testResult) setTestResult(null)

    // Update YAML error markers in the Monaco gutter
    const monaco = monacoRef.current
    const editorInst = editorRef.current
    if (monaco && editorInst) {
      const model = editorInst.getModel()
      if (model) {
        try {
          yamlLoad(yaml)
          monaco.editor.setModelMarkers(model, 'yaml', [])
        } catch (e) {
          if (e instanceof YAMLException && e.mark) {
            const { line, column } = e.mark
            monaco.editor.setModelMarkers(model, 'yaml', [
              {
                startLineNumber: line + 1,
                endLineNumber: line + 1,
                startColumn: column + 1,
                endColumn: column + 2,
                message: e.message,
                severity: monaco.MarkerSeverity.Error,
              },
            ])
          }
        }
      }
    }
  }

  const handleSave = useCallback(() => {
    setSaveError(null)
    const errors = validateSigmaYaml(editorYaml)
    setValidationErrors(errors)
    if (errors.length > 0) return
    saveMutation.mutate(editorYaml)
  }, [editorYaml, saveMutation])

  const handleTest = useCallback(() => {
    setTestResult(null)
    const errors = validateSigmaYaml(editorYaml)
    setValidationErrors(errors)
    if (errors.length > 0) return
    testMutation.mutate(editorYaml)
  }, [editorYaml, testMutation])

  const handleFormat = useCallback(() => {
    const formatted = formatYaml(editorYaml)
    setEditorYaml(formatted)
  }, [editorYaml])

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
          setTestResult(null)
          setShowEditor(true)
        }
      }
      reader.readAsText(file)
      // Reset so the same file can be re-imported
      e.target.value = ''
    },
    [],
  )

  const handleRuleClick = useCallback(async (rule: Rule) => {
    setLoadingRuleId(rule.id)
    setValidationErrors([])
    setSaveError(null)
    setTestResult(null)
    try {
      const resp = await apiClient.get<RuleDetail>(`/rules/${rule.id}`)
      setEditorYaml(resp.data.content)
      setEditingRuleId(rule.id)
      setShowEditor(true)
    } catch {
      // leave loadingRuleId cleared so the row is re-clickable
    } finally {
      setLoadingRuleId(null)
    }
  }, [])

  const handleEditorClose = useCallback(() => {
    setShowEditor(false)
    setEditingRuleId(null)
    setValidationErrors([])
    setSaveError(null)
    setTestResult(null)
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
            onClick={() => { setEditingRuleId(null); setEditorYaml(EXAMPLE_SIGMA); setShowEditor(true); setValidationErrors([]); setSaveError(null); setTestResult(null) }}
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
            <div
              key={rule.id}
              role="button"
              tabIndex={0}
              onClick={() => void handleRuleClick(rule)}
              onKeyDown={(e) => e.key === 'Enter' && void handleRuleClick(rule)}
              className="grid grid-cols-[1fr_70px_100px_80px_80px_80px_60px] gap-2 px-3 py-[6px] border-b border-section items-center hover:bg-page cursor-pointer"
            >
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
                {loadingRuleId === rule.id
                  ? <div className="w-[6px] h-[6px] rounded-full bg-blue animate-pulse" />
                  : <div className={`w-[6px] h-[6px] rounded-full ${rule.enabled ? 'bg-status-ok' : 'bg-border'}`} />
                }
              </div>
            </div>
          ))}
        </div>

        {/* Editor modal */}
        {showEditor && (
          <div className="fixed inset-0 bg-overlay z-50 flex items-center justify-center">
            <div className="bg-surface rounded-lg shadow-panel w-[800px] max-h-[85vh] flex flex-col">
              <div className="flex items-center justify-between px-5 py-3 border-b border-border">
                <h2 className="text-[13px] font-semibold text-text-primary">
                  {editingRuleId ? 'Edit Rule' : 'New Sigma Rule'}
                </h2>
                <div className="flex items-center gap-2">
                  <button
                    onClick={handleFileImport}
                    className="text-[11px] text-blue hover:underline"
                  >
                    Import file
                  </button>
                  <button onClick={handleEditorClose} className="text-text-muted text-lg leading-none">&times;</button>
                </div>
              </div>

              <div className="flex-1 overflow-auto p-4">
                {/* Monaco YAML editor */}
                <div className="border border-border rounded-md overflow-hidden">
                  <Editor
                    height="400px"
                    defaultLanguage="yaml"
                    value={editorYaml}
                    onChange={handleEditorChange}
                    beforeMount={handleBeforeMount}
                    onMount={handleEditorMount}
                    theme={getMonacoTheme(theme)}
                    loading={
                      <div className="flex items-center justify-center h-[400px] bg-page text-text-muted text-[11px]">
                        Loading editor...
                      </div>
                    }
                    options={{
                      minimap: { enabled: false },
                      fontSize: 11,
                      fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
                      lineNumbers: 'on',
                      scrollBeyondLastLine: false,
                      wordWrap: 'on',
                      automaticLayout: true,
                      padding: { top: 8, bottom: 8 },
                    }}
                  />
                </div>

                {/* Test result */}
                {testResult && (
                  <div className={`mt-2 px-3 py-2 rounded text-[11px] flex items-start gap-2 ${
                    testResult.matched
                      ? 'bg-resolved-bg text-resolved-text'
                      : testResult.errors.length > 0
                        ? 'bg-crit-bg text-crit-text'
                        : 'bg-warn-bg text-warn-text'
                  }`}>
                    <span className="font-medium flex-shrink-0">
                      {testResult.matched
                        ? '✓ Matched'
                        : testResult.errors.length > 0
                          ? '⚠ Error'
                          : '✗ No match'}
                    </span>
                    {testResult.errors.length > 0 && (
                      <span>{testResult.errors.join('; ')}</span>
                    )}
                  </div>
                )}

                {/* Validation errors */}
                {validationErrors.length > 0 && (
                  <div className="mt-2 space-y-1">
                    {validationErrors.map((err, i) => (
                      <div key={i} className="text-[11px] text-crit-text flex items-center gap-1">
                        <span className="inline-block w-[14px] h-[14px] rounded-full bg-crit-bg text-crit-text text-center text-[9px] leading-[14px] font-bold flex-shrink-0">!</span>
                        {err}
                      </div>
                    ))}
                  </div>
                )}

                {/* API error */}
                {saveError && (
                  <div className="mt-2 text-[11px] text-crit-text bg-crit-bg rounded px-3 py-2">
                    {saveError}
                  </div>
                )}
              </div>

              <div className="flex items-center gap-2 px-5 py-3 border-t border-border">
                {/* Left: utility actions */}
                <button
                  className="h-[28px] px-3 border border-border text-[11px] text-text-secondary rounded-md hover:border-blue transition-colors"
                  onClick={handleFormat}
                  title="Auto-format YAML"
                >
                  Format
                </button>
                <button
                  className="h-[28px] px-3 border border-border text-[11px] text-text-secondary rounded-md hover:border-blue transition-colors disabled:opacity-50"
                  onClick={handleTest}
                  disabled={testMutation.isPending}
                  title="Test rule against a sample event"
                >
                  {testMutation.isPending ? 'Testing...' : 'Test Rule'}
                </button>
                <div className="flex-1" />
                {/* Right: primary actions */}
                <button
                  className="h-[30px] px-4 border border-border text-[12px] text-text-secondary rounded-md"
                  onClick={handleEditorClose}
                >
                  Cancel
                </button>
                <button
                  className="h-[30px] px-4 bg-blue text-white text-[12px] rounded-md hover:opacity-90 disabled:opacity-50"
                  onClick={handleSave}
                  disabled={saveMutation.isPending}
                >
                  {saveMutation.isPending ? 'Saving...' : 'Save Rule'}
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
