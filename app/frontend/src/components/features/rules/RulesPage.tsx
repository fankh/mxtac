import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
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

async function fetchRules(): Promise<Rule[]> {
  const resp = await apiClient.get('/rules')
  return resp.data
}

export function RulesPage() {
  const [levelFilter, setLevelFilter] = useState<string | null>(null)
  const [enabledFilter, setEnabledFilter] = useState<boolean | null>(null)
  const [search, setSearch] = useState('')
  const [showEditor, setShowEditor] = useState(false)
  const [editorYaml, setEditorYaml] = useState(EXAMPLE_SIGMA)

  const { data = [], isLoading, refetch } = useQuery({
    queryKey: ['rules'],
    queryFn: fetchRules,
  })

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
            placeholder="Search rules…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <button
            onClick={() => setShowEditor(true)}
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
            <div className="flex items-center justify-center h-32 text-text-muted text-sm">Loading rules…</div>
          )}

          {!isLoading && visible.length === 0 && (
            <div className="flex flex-col items-center justify-center h-32 gap-2 text-text-muted text-sm">
              <div>No rules loaded</div>
              <button onClick={() => setShowEditor(true)} className="text-blue text-[11px] hover:underline">
                Create your first rule →
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
                <button onClick={() => setShowEditor(false)} className="text-text-muted text-lg">×</button>
              </div>
              <div className="flex-1 overflow-auto p-4">
                <textarea
                  className="w-full h-[400px] text-[11px] font-mono bg-page border border-border rounded-md p-3 text-text-primary focus:outline-none focus:border-blue resize-none"
                  value={editorYaml}
                  onChange={(e) => setEditorYaml(e.target.value)}
                  spellCheck={false}
                />
              </div>
              <div className="flex items-center gap-2 px-5 py-3 border-t border-border">
                <button
                  className="flex-1 h-[30px] bg-blue text-white text-[12px] rounded-md hover:opacity-90"
                  onClick={() => { setShowEditor(false); refetch() }}
                >
                  Save Rule
                </button>
                <button
                  className="h-[30px] px-4 border border-border text-[12px] text-text-secondary rounded-md"
                  onClick={() => setShowEditor(false)}
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
