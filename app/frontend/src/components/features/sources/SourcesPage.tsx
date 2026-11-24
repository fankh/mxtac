import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Database, Pencil, Play, PlugZap, Plus, RefreshCw, Search, Square, Trash2, X } from 'lucide-react'
import { Page } from '@/components/layout/Page'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { EmptyState } from '@/components/ui/empty-state'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { apiErrorMessage, connectorsApi } from '@/lib/api'
import { cn, fmtNum } from '@/lib/utils'
import { useUIStore } from '@/stores/uiStore'
import type { Connector } from '@/types/api'
import { ConfirmDialog } from '@/components/shared/ConfirmDialog'
import { ConnectorDetailSheet } from './ConnectorDetailSheet'
import { ConnectorFormDialog } from './ConnectorFormDialog'
import { IngestHelpCard } from './IngestHelpCard'
import { CONNECTOR_TYPES, connectorStatus, connectorTypeInfo, formatLastSeen } from './connectorTypes'

const RUNNING = new Set(['active', 'connecting'])

type FormState = { mode: 'add' } | { mode: 'edit'; connector: Connector } | null

export function SourcesPage() {
  const queryClient = useQueryClient()
  const addNotification = useUIStore((s) => s.addNotification)

  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState<string | null>(null)
  const [form, setForm] = useState<FormState>(null)
  const [detailId, setDetailId] = useState<string | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<Connector | null>(null)

  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['connectors'],
    queryFn: connectorsApi.list,
    refetchInterval: 30_000,
  })
  const connectors = useMemo(() => data ?? [], [data])

  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: ['connectors'] })
    queryClient.invalidateQueries({ queryKey: ['connector-health'] })
  }
  const fail = (title: string, fallback: string) => (err: unknown) =>
    addNotification({ type: 'error', title, message: apiErrorMessage(err, fallback) })

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => connectorsApi.update(id, { enabled }),
    onSuccess: refresh,
    onError: fail('Update failed', 'Could not change the enabled setting'),
  })

  const startMutation = useMutation({
    mutationFn: (c: Connector) => connectorsApi.start(c.id),
    onSuccess: (c) => {
      refresh()
      addNotification({ type: 'success', title: 'Source started', message: c.name })
    },
    onError: fail('Start failed', 'Could not start the source'),
  })

  const stopMutation = useMutation({
    mutationFn: (c: Connector) => connectorsApi.stop(c.id),
    onSuccess: (c) => {
      refresh()
      addNotification({ type: 'success', title: 'Source stopped', message: c.name })
    },
    onError: fail('Stop failed', 'Could not stop the source'),
  })

  const testMutation = useMutation({
    mutationFn: (c: Connector) => connectorsApi.test(c.id),
    onSuccess: (result, c) => {
      refresh()
      addNotification({
        type: result.reachable ? 'success' : 'warning',
        title: result.reachable ? `${c.name} is reachable` : `${c.name} is not reachable`,
        message: result.message,
      })
    },
    onError: fail('Test failed', 'Could not run the connection test'),
  })

  const deleteMutation = useMutation({
    // DELETE only removes the record, so a running source is stopped first.
    mutationFn: async (c: Connector) => {
      if (RUNNING.has(c.status) && connectorTypeInfo(c.connector_type)?.canRun) await connectorsApi.stop(c.id)
      return connectorsApi.delete(c.id)
    },
    onSuccess: (_, c) => {
      refresh()
      setDeleteTarget(null)
      if (detailId === c.id) setDetailId(null)
      addNotification({ type: 'success', title: 'Source deleted', message: c.name })
    },
    onError: fail('Delete failed', 'Could not delete the source'),
  })

  const visible = useMemo(() => {
    const q = search.trim().toLowerCase()
    return connectors.filter((c) => {
      if (typeFilter && c.connector_type !== typeFilter) return false
      if (!q) return true
      return c.name.toLowerCase().includes(q) || c.connector_type.toLowerCase().includes(q)
    })
  }, [connectors, search, typeFilter])

  const stats = useMemo(() => ({
    total: connectors.length,
    running: connectors.filter((c) => RUNNING.has(c.status)).length,
    errors: connectors.filter((c) => c.status === 'error').length,
    events: connectors.reduce((sum, c) => sum + c.events_total, 0),
  }), [connectors])

  const genericSources = useMemo(() => connectors.filter((c) => c.connector_type === 'generic'), [connectors])
  const detail = connectors.find((c) => c.id === detailId) ?? null

  return (
    <Page
      title="Data sources"
      description="Connectors that bring events into MxTac"
      actions={
        <Button className="gap-1.5" onClick={() => setForm({ mode: 'add' })}>
          <Plus className="h-3.5 w-3.5" />
          Add source
        </Button>
      }
    >
      <div className="grid gap-4 md:grid-cols-4">
        {[
          { label: 'Sources', value: stats.total },
          { label: 'Running', value: stats.running },
          { label: 'In error', value: stats.errors },
          { label: 'Events received', value: stats.events },
        ].map((s) => (
          <Card key={s.label}>
            <CardContent className="p-4">
              <p className="text-[11px] text-muted-foreground">{s.label}</p>
              {isLoading
                ? <Skeleton className="mt-1 h-6 w-16" />
                : <p className="text-lg font-bold text-foreground">{isError ? '–' : fmtNum(s.value)}</p>}
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <div className="relative w-full max-w-xs">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            className="h-8 pl-8 pr-8"
            placeholder="Search sources"
            aria-label="Search sources"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Escape') setSearch('') }}
          />
          {search && (
            <Button
              variant="ghost"
              size="icon"
              title="Clear search"
              className="absolute right-1 top-1/2 h-6 w-6 -translate-y-1/2"
              onClick={() => setSearch('')}
            >
              <X className="h-3.5 w-3.5" />
            </Button>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-1">
          <Button
            variant={typeFilter === null ? 'secondary' : 'ghost'}
            aria-pressed={typeFilter === null}
            onClick={() => setTypeFilter(null)}
          >
            All
          </Button>
          {CONNECTOR_TYPES.map((t) => (
            <Button
              key={t.type}
              variant={typeFilter === t.type ? 'secondary' : 'ghost'}
              aria-pressed={typeFilter === t.type}
              onClick={() => setTypeFilter(typeFilter === t.type ? null : t.type)}
            >
              {t.label}
            </Button>
          ))}
        </div>
      </div>

      <Card>
        <CardContent className="p-0">
          {isLoading && (
            <div className="space-y-2 p-4" aria-label="Loading sources">
              {[0, 1, 2].map((i) => <Skeleton key={i} className="h-8 w-full" />)}
            </div>
          )}

          {isError && (
            <div className="flex flex-col items-center gap-3 p-8 text-center">
              <p className="text-[12px] text-destructive">Could not load data sources.</p>
              <Button variant="outline" className="gap-1.5" onClick={() => refetch()}>
                <RefreshCw className="h-3.5 w-3.5" />
                Retry
              </Button>
            </div>
          )}

          {!isLoading && !isError && connectors.length === 0 && (
            <EmptyState
              icon={Database}
              title="No data sources yet"
              description="Add Wazuh, Zeek, Suricata, syslog or a generic webhook to start receiving events."
              action={<Button onClick={() => setForm({ mode: 'add' })}>Add source</Button>}
            />
          )}

          {!isLoading && !isError && connectors.length > 0 && visible.length === 0 && (
            <EmptyState icon={Search} title="No sources match" description="Change the search text or the type filter." />
          )}

          {!isLoading && !isError && visible.length > 0 && (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Source</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Events</TableHead>
                  <TableHead className="text-right">Errors</TableHead>
                  <TableHead>Last seen</TableHead>
                  <TableHead>Enabled</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {visible.map((c) => {
                  const info = connectorTypeInfo(c.connector_type)
                  const status = connectorStatus(c.status)
                  const running = RUNNING.has(c.status)
                  const Icon = info?.icon ?? Database
                  return (
                    <TableRow key={c.id}>
                      <TableCell className="text-[12px]">
                        <div className="flex items-center gap-2">
                          <Icon className="h-4 w-4 shrink-0 text-muted-foreground" />
                          <div className="min-w-0">
                            <Button
                              variant="link"
                              className="h-auto p-0 text-[12px] font-medium text-foreground"
                              onClick={() => setDetailId(c.id)}
                            >
                              {c.name}
                            </Button>
                            <p className="text-[11px] text-muted-foreground">{info?.label ?? c.connector_type}</p>
                          </div>
                        </div>
                      </TableCell>
                      <TableCell className="text-[12px]">
                        <span
                          title={c.error_message ?? undefined}
                          className={cn('inline-flex rounded-full border px-2 py-0.5 text-[10px] font-medium', status.cls)}
                        >
                          {status.label}
                        </span>
                      </TableCell>
                      <TableCell className="text-right text-[12px] tabular-nums">{fmtNum(c.events_total)}</TableCell>
                      <TableCell className={cn('text-right text-[12px] tabular-nums', c.errors_total > 0 && 'text-destructive')}>
                        {fmtNum(c.errors_total)}
                      </TableCell>
                      <TableCell className="text-[12px] text-muted-foreground">{formatLastSeen(c.last_seen_at)}</TableCell>
                      <TableCell>
                        <Switch
                          checked={c.enabled}
                          aria-label={`${c.enabled ? 'Disable' : 'Enable'} ${c.name}`}
                          disabled={toggleMutation.isPending}
                          onCheckedChange={(enabled) => toggleMutation.mutate({ id: c.id, enabled })}
                        />
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center justify-end gap-0.5">
                          {info?.canRun && (running ? (
                            <Button
                              variant="ghost" size="icon" title={`Stop ${c.name}`}
                              disabled={stopMutation.isPending}
                              onClick={() => stopMutation.mutate(c)}
                            >
                              <Square className="h-3.5 w-3.5" />
                            </Button>
                          ) : (
                            <Button
                              variant="ghost" size="icon" title={`Start ${c.name}`}
                              disabled={startMutation.isPending}
                              onClick={() => startMutation.mutate(c)}
                            >
                              <Play className="h-3.5 w-3.5" />
                            </Button>
                          ))}
                          {info?.canTest && (
                            <Button
                              variant="ghost" size="icon" title={`Test connection to ${c.name}`}
                              disabled={testMutation.isPending}
                              onClick={() => testMutation.mutate(c)}
                            >
                              <PlugZap className="h-3.5 w-3.5" />
                            </Button>
                          )}
                          <Button
                            variant="ghost" size="icon" title={`Edit ${c.name}`}
                            onClick={() => setForm({ mode: 'edit', connector: c })}
                          >
                            <Pencil className="h-3.5 w-3.5" />
                          </Button>
                          <Button
                            variant="ghost" size="icon" title={`Delete ${c.name}`}
                            className="hover:text-destructive"
                            onClick={() => setDeleteTarget(c)}
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {!isLoading && !isError && <IngestHelpCard sources={genericSources} />}

      {form && (
        <ConnectorFormDialog
          connector={form.mode === 'edit' ? form.connector : undefined}
          onClose={() => setForm(null)}
        />
      )}

      <ConnectorDetailSheet connector={detail} onClose={() => setDetailId(null)} />

      <ConfirmDialog
        open={deleteTarget !== null}
        title="Delete data source"
        description={`${deleteTarget?.name ?? 'This source'} will be removed. Events already received are kept.`}
        confirmLabel="Delete"
        pendingLabel="Deleting…"
        pending={deleteMutation.isPending}
        onConfirm={() => { if (deleteTarget) deleteMutation.mutate(deleteTarget) }}
        onCancel={() => setDeleteTarget(null)}
      />
    </Page>
  )
}
