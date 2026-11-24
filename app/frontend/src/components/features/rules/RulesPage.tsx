import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  ChevronLeft, ChevronRight, FileCode2, FlaskConical, Pencil, Plus, RefreshCw, RotateCw, Search, ThumbsDown, Trash2,
  Upload, X,
} from 'lucide-react'
import { Page } from '@/components/layout/Page'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { EmptyState } from '@/components/ui/empty-state'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { apiErrorMessage, rulesApi } from '@/lib/api'
import { cn, fmtNum } from '@/lib/utils'
import { useAuthStore } from '@/stores/authStore'
import { useUIStore } from '@/stores/uiStore'
import type { Rule } from '@/types/api'
import { ConfirmDialog } from '@/components/shared/ConfirmDialog'
import { RoleNotice } from '@/components/shared/RoleNotice'
import { canReadRules } from '@/lib/roles'
import { RuleEditorDialog } from './RuleEditorDialog'
import { RuleImportDialog } from './RuleImportDialog'
import { RuleTestDialog } from './RuleTestDialog'

const PAGE_SIZE = 50
const LEVELS = ['critical', 'high', 'medium', 'low', 'informational'] as const
const LEVEL_CLASS: Record<string, string> = {
  critical: 'sev-critical',
  high: 'sev-high',
  medium: 'sev-medium',
  low: 'sev-low',
  informational: 'sev-info',
}
/** Roles with the rules:write permission (see backend core/rbac.py). */
const WRITE_ROLES = new Set(['engineer', 'admin'])

type EditorState = { ruleId: string | null } | null

function logsourceText(rule: Rule): string {
  const { product, category, service } = rule.logsource ?? {}
  return [product, category, service].filter(Boolean).join(' / ') || '–'
}

const TITLE = 'Sigma rules'
const DESCRIPTION = 'Detection rules evaluated against incoming events'

/** Rule management. The backend limits reading rules to hunter, engineer and admin. */
export function RulesPage() {
  const role = useAuthStore((s) => s.user?.role)

  if (role && !canReadRules(role)) {
    return (
      <Page title={TITLE} description={DESCRIPTION}>
        <RoleNotice
          title="Sigma rules need the hunter role"
          description="Hunter accounts can view and test rules. Engineer and admin accounts can also change them."
        />
      </Page>
    )
  }
  return <RulesWorkspace />
}

function RulesWorkspace() {
  const queryClient = useQueryClient()
  const addNotification = useUIStore((s) => s.addNotification)
  const role = useAuthStore((s) => s.user?.role)
  const canWrite = role !== undefined && WRITE_ROLES.has(role)

  const [search, setSearch] = useState('')
  const [level, setLevel] = useState('all')
  const [state, setState] = useState('all')
  const [page, setPage] = useState(1)
  const [editor, setEditor] = useState<EditorState>(null)
  const [importOpen, setImportOpen] = useState(false)
  const [testTarget, setTestTarget] = useState<Rule | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<Rule | null>(null)
  const [fpTarget, setFpTarget] = useState<Rule | null>(null)

  const rulesQuery = useQuery({ queryKey: ['rules'], queryFn: () => rulesApi.list() })
  const statsQuery = useQuery({ queryKey: ['rules-stats'], queryFn: rulesApi.stats })
  const rules = useMemo(() => rulesQuery.data ?? [], [rulesQuery.data])

  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: ['rules'] })
    queryClient.invalidateQueries({ queryKey: ['rules-stats'] })
  }
  const fail = (title: string, fallback: string) => (err: unknown) =>
    addNotification({ type: 'error', title, message: apiErrorMessage(err, fallback) })

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => rulesApi.update(id, { enabled }),
    onSuccess: refresh,
    onError: fail('Update failed', 'Could not change the rule state'),
  })

  const deleteMutation = useMutation({
    mutationFn: (rule: Rule) => rulesApi.delete(rule.id),
    onSuccess: (_, rule) => {
      refresh()
      setDeleteTarget(null)
      addNotification({ type: 'success', title: 'Rule deleted', message: rule.title })
    },
    onError: fail('Delete failed', 'Could not delete the rule'),
  })

  const fpMutation = useMutation({
    mutationFn: (rule: Rule) => rulesApi.markFalsePositive(rule.id),
    onSuccess: (_, rule) => {
      refresh()
      setFpTarget(null)
      addNotification({ type: 'success', title: 'False positive recorded', message: rule.title })
    },
    onError: fail('Could not record the false positive', 'The request failed'),
  })

  const reloadMutation = useMutation({
    mutationFn: rulesApi.reload,
    onSuccess: (result) => {
      refresh()
      addNotification({
        type: 'success',
        title: 'Detection engine reloaded',
        message: `${result.reloaded} of ${result.total_rules} rules loaded`,
      })
    },
    onError: fail('Reload failed', 'Could not reload the detection engine'),
  })

  const visible = useMemo(() => {
    const q = search.trim().toLowerCase()
    return rules.filter((r) => {
      if (level !== 'all' && r.level !== level) return false
      if (state === 'enabled' && !r.enabled) return false
      if (state === 'disabled' && r.enabled) return false
      if (!q) return true
      return r.title.toLowerCase().includes(q)
        || r.id.toLowerCase().includes(q)
        || r.technique_ids.some((t) => t.toLowerCase().includes(q))
    })
  }, [rules, search, level, state])

  const pageCount = Math.max(1, Math.ceil(visible.length / PAGE_SIZE))
  useEffect(() => { setPage(1) }, [search, level, state])
  useEffect(() => { if (page > pageCount) setPage(pageCount) }, [page, pageCount])
  const pageRows = visible.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE)

  const stats = statsQuery.data
  const statCards = [
    { label: 'Rules', value: stats?.total },
    { label: 'Enabled', value: stats?.enabled },
    { label: 'Critical', value: stats ? stats.by_level.critical ?? 0 : undefined },
    { label: 'High', value: stats ? stats.by_level.high ?? 0 : undefined },
  ]
  const { isLoading, isError } = rulesQuery

  return (
    <Page
      title={TITLE}
      description={DESCRIPTION}
      actions={canWrite && (
        <>
          <Button
            variant="outline" className="gap-1.5"
            title="Reload all rules from the database into the detection engine"
            disabled={reloadMutation.isPending}
            onClick={() => reloadMutation.mutate()}
          >
            <RotateCw className={cn('h-3.5 w-3.5', reloadMutation.isPending && 'animate-spin')} />
            Reload engine
          </Button>
          <Button variant="outline" className="gap-1.5" onClick={() => setImportOpen(true)}>
            <Upload className="h-3.5 w-3.5" />
            Import
          </Button>
          <Button className="gap-1.5" onClick={() => setEditor({ ruleId: null })}>
            <Plus className="h-3.5 w-3.5" />
            New rule
          </Button>
        </>
      )}
    >
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {statCards.map((s) => (
          <Card key={s.label}>
            <CardContent className="p-4">
              <p className="text-[11px] text-muted-foreground">{s.label}</p>
              {statsQuery.isLoading
                ? <Skeleton className="mt-1 h-6 w-16" />
                : <p className="text-lg font-bold text-foreground">{s.value === undefined ? '–' : fmtNum(s.value)}</p>}
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <div className="relative w-full max-w-xs">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            className="h-8 pl-8 pr-8"
            placeholder="Search by title, ID or technique"
            aria-label="Search rules"
            data-shortcut-search=""
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Escape') setSearch('') }}
          />
          {search && (
            <Button
              variant="ghost" size="icon" title="Clear search"
              className="absolute right-1 top-1/2 h-6 w-6 -translate-y-1/2"
              onClick={() => setSearch('')}
            >
              <X className="h-3.5 w-3.5" />
            </Button>
          )}
        </div>
        <Select value={level} onValueChange={setLevel}>
          <SelectTrigger className="h-8 w-40" aria-label="Level"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All levels</SelectItem>
            {LEVELS.map((l) => <SelectItem key={l} value={l} className="capitalize">{l}</SelectItem>)}
          </SelectContent>
        </Select>
        <Select value={state} onValueChange={setState}>
          <SelectTrigger className="h-8 w-36" aria-label="State"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All states</SelectItem>
            <SelectItem value="enabled">Enabled</SelectItem>
            <SelectItem value="disabled">Disabled</SelectItem>
          </SelectContent>
        </Select>
        {!isLoading && !isError && (
          <span className="ml-auto text-[11px] text-muted-foreground">
            {fmtNum(visible.length)} of {fmtNum(rules.length)} rules
          </span>
        )}
      </div>

      <Card>
        <CardContent className="p-0">
          {isLoading && (
            <div className="space-y-2 p-4" aria-label="Loading rules">
              {[0, 1, 2, 3, 4].map((i) => <Skeleton key={i} className="h-8 w-full" />)}
            </div>
          )}

          {isError && (
            <div className="flex flex-col items-center gap-3 p-8 text-center">
              <p className="text-[12px] text-destructive">Could not load rules.</p>
              <Button variant="outline" className="gap-1.5" onClick={() => rulesQuery.refetch()}>
                <RefreshCw className="h-3.5 w-3.5" />
                Retry
              </Button>
            </div>
          )}

          {!isLoading && !isError && rules.length === 0 && (
            <EmptyState
              icon={FileCode2}
              title="No rules yet"
              description={canWrite ? 'Create a rule or import Sigma YAML to start detecting.' : 'No Sigma rules have been added.'}
              action={canWrite ? <Button onClick={() => setEditor({ ruleId: null })}>New rule</Button> : undefined}
            />
          )}

          {!isLoading && !isError && rules.length > 0 && visible.length === 0 && (
            <EmptyState icon={Search} title="No rules match" description="Change the search text or the filters." />
          )}

          {!isLoading && !isError && pageRows.length > 0 && (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Rule</TableHead>
                  <TableHead>Level</TableHead>
                  <TableHead>Techniques</TableHead>
                  <TableHead>Log source</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Hits</TableHead>
                  <TableHead className="text-right">False positives</TableHead>
                  <TableHead>Enabled</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {pageRows.map((rule) => (
                  <TableRow key={rule.id}>
                    <TableCell className="max-w-[320px] text-[12px]">
                      <Button
                        variant="link"
                        className="block h-auto max-w-full truncate p-0 text-left text-[12px] font-medium text-foreground"
                        title={rule.title}
                        onClick={() => setEditor({ ruleId: rule.id })}
                      >
                        {rule.title}
                      </Button>
                      <p className="truncate font-mono text-[11px] text-muted-foreground">{rule.id}</p>
                    </TableCell>
                    <TableCell className="text-[12px]">
                      <span className={cn('inline-flex rounded-full border px-2 py-0.5 text-[10px] font-medium capitalize', LEVEL_CLASS[rule.level] ?? 'sev-info')}>
                        {rule.level}
                      </span>
                    </TableCell>
                    <TableCell className="text-[12px]">
                      <div className="flex flex-wrap gap-1">
                        {rule.technique_ids.slice(0, 2).map((t) => (
                          <span key={t} className="rounded border border-border bg-muted px-1.5 font-mono text-[10px] text-foreground">{t}</span>
                        ))}
                        {rule.technique_ids.length > 2 && (
                          <span className="text-[11px] text-muted-foreground" title={rule.technique_ids.slice(2).join(', ')}>
                            +{rule.technique_ids.length - 2}
                          </span>
                        )}
                        {rule.technique_ids.length === 0 && <span className="text-muted-foreground">–</span>}
                      </div>
                    </TableCell>
                    <TableCell className="text-[12px] text-muted-foreground">{logsourceText(rule)}</TableCell>
                    <TableCell className="text-[12px] capitalize text-muted-foreground">{rule.status}</TableCell>
                    <TableCell className="text-right text-[12px] tabular-nums">{fmtNum(rule.hit_count)}</TableCell>
                    <TableCell className="text-right text-[12px] tabular-nums">{fmtNum(rule.fp_count)}</TableCell>
                    <TableCell>
                      <Switch
                        checked={rule.enabled}
                        aria-label={`${rule.enabled ? 'Disable' : 'Enable'} ${rule.title}`}
                        disabled={!canWrite || toggleMutation.isPending}
                        onCheckedChange={(enabled) => toggleMutation.mutate({ id: rule.id, enabled })}
                      />
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center justify-end gap-0.5">
                        <Button variant="ghost" size="icon" title={`Test ${rule.title}`} onClick={() => setTestTarget(rule)}>
                          <FlaskConical className="h-3.5 w-3.5" />
                        </Button>
                        <Button
                          variant="ghost" size="icon" title={`Mark a false positive for ${rule.title}`}
                          onClick={() => setFpTarget(rule)}
                        >
                          <ThumbsDown className="h-3.5 w-3.5" />
                        </Button>
                        {canWrite && (
                          <>
                            <Button
                              variant="ghost" size="icon" title={`Edit ${rule.title}`}
                              onClick={() => setEditor({ ruleId: rule.id })}
                            >
                              <Pencil className="h-3.5 w-3.5" />
                            </Button>
                            <Button
                              variant="ghost" size="icon" title={`Delete ${rule.title}`}
                              className="hover:text-destructive"
                              onClick={() => setDeleteTarget(rule)}
                            >
                              <Trash2 className="h-3.5 w-3.5" />
                            </Button>
                          </>
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}

          {!isLoading && !isError && pageCount > 1 && (
            <div className="flex items-center justify-between border-t border-border px-4 py-2">
              <span className="text-[11px] text-muted-foreground">Page {page} of {pageCount}</span>
              <div className="flex items-center gap-1">
                <Button variant="outline" size="icon" title="Previous page" disabled={page <= 1} onClick={() => setPage(page - 1)}>
                  <ChevronLeft className="h-3.5 w-3.5" />
                </Button>
                <Button variant="outline" size="icon" title="Next page" disabled={page >= pageCount} onClick={() => setPage(page + 1)}>
                  <ChevronRight className="h-3.5 w-3.5" />
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {editor && <RuleEditorDialog ruleId={editor.ruleId} canWrite={canWrite} onClose={() => setEditor(null)} />}
      {importOpen && <RuleImportDialog onClose={() => setImportOpen(false)} />}
      {testTarget && <RuleTestDialog rule={testTarget} onClose={() => setTestTarget(null)} />}

      <ConfirmDialog
        open={deleteTarget !== null}
        title="Delete rule"
        description={`${deleteTarget?.title ?? 'This rule'} will be removed from the database and the detection engine.`}
        confirmLabel="Delete"
        pendingLabel="Deleting…"
        pending={deleteMutation.isPending}
        onConfirm={() => { if (deleteTarget) deleteMutation.mutate(deleteTarget) }}
        onCancel={() => setDeleteTarget(null)}
      />

      <ConfirmDialog
        open={fpTarget !== null}
        title="Mark false positive"
        description={`This adds one to the false positive count of ${fpTarget?.title ?? 'this rule'}. It cannot be undone.`}
        confirmLabel="Mark false positive"
        pendingLabel="Saving…"
        pending={fpMutation.isPending}
        destructive={false}
        onConfirm={() => { if (fpTarget) fpMutation.mutate(fpTarget) }}
        onCancel={() => setFpTarget(null)}
      />
    </Page>
  )
}
