import { useState, type FormEvent, type ReactNode } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ShieldAlert } from 'lucide-react'
import type { Detection, Incident, IncidentUpdate } from '@/types/api'
import { incidentsApi } from '@/lib/api'
import { useAuthStore } from '@/stores/authStore'
import { useUIStore } from '@/stores/uiStore'
import { Button } from '@/components/ui/button'
import { EmptyState } from '@/components/ui/empty-state'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@/components/ui/sheet'
import { Skeleton } from '@/components/ui/skeleton'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { ScoreCircle, SeverityPill } from '@/components/shared/SeverityBadge'
import { StatusPill } from '@/components/shared/StatusPill'
import { ErrorCard } from '../detections/ListControls'
import { OptionSelect } from '../detections/OptionSelect'
import {
  SEVERITY_LABELS,
  SEVERITY_OPTIONS,
  apiErrorMessage,
  canWrite,
  formatDateTime,
} from '../detections/utils'
import { IncidentStatusPill } from './IncidentStatusPill'
import { IncidentTimeline } from './IncidentTimeline'
import {
  INCIDENT_STATUS_LABELS,
  formatDuration,
  isValidEmail,
  reachableStatuses,
} from './incidentUtils'

interface IncidentPanelProps {
  /** Incident to show; the panel is closed while this is null. */
  incident: Incident | null
  onClose: () => void
}

const SEVERITY_SELECT_OPTIONS = SEVERITY_OPTIONS.map((value) => ({ value, label: SEVERITY_LABELS[value] }))

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[110px_1fr] gap-2 border-b border-border py-1.5 last:border-0">
      <dt className="text-[11px] font-medium text-muted-foreground">{label}</dt>
      <dd className="break-words text-[12px] text-foreground">{children}</dd>
    </div>
  )
}

function Chips({ values }: { values: string[] }) {
  if (values.length === 0) return <span className="text-muted-foreground">—</span>
  return (
    <span className="flex flex-wrap gap-1">
      {values.map((value) => (
        <span key={value} className="rounded border border-border bg-muted px-1.5 py-0.5 font-mono text-[11px]">
          {value}
        </span>
      ))}
    </span>
  )
}

function LinkedDetections({ detections, missing }: { detections: Detection[]; missing: number }) {
  if (detections.length === 0 && missing === 0) {
    return (
      <EmptyState
        icon={ShieldAlert}
        title="No linked detections"
        description="Link detections by creating an incident from the detections list."
      />
    )
  }
  return (
    <div className="space-y-2">
      <ul className="space-y-2">
        {detections.map((d) => (
          <li key={d.id} className="flex items-start gap-2.5 rounded-lg border border-border p-2.5">
            <ScoreCircle score={d.score} severity={d.severity} />
            <div className="min-w-0 flex-1">
              <p className="truncate text-[12px] font-medium text-foreground">{d.name}</p>
              <p className="truncate text-[11px] text-muted-foreground">
                <span className="font-mono">{d.technique_id}</span> · {d.host} · {formatDateTime(d.time)}
              </p>
            </div>
            <StatusPill status={d.status} />
          </li>
        ))}
      </ul>
      {missing > 0 && (
        <p className="text-[11px] text-muted-foreground">
          {missing} linked detection{missing === 1 ? ' has' : 's have'} been deleted.
        </p>
      )}
    </div>
  )
}

function PanelBody({ incident }: { incident: Incident }) {
  const queryClient = useQueryClient()
  const addNotification = useUIStore((s) => s.addNotification)
  const writable = canWrite(useAuthStore((s) => s.user?.role))
  const [tab, setTab] = useState('details')

  const detailQuery = useQuery({
    queryKey: ['incident-detail', incident.id],
    queryFn: () => incidentsApi.get(incident.id),
  })
  const detail = detailQuery.data
  const current: Incident = detail ?? incident

  const [assignee, setAssignee] = useState(incident.assigned_to ?? '')

  function invalidate() {
    queryClient.invalidateQueries({ queryKey: ['incidents'] })
    queryClient.invalidateQueries({ queryKey: ['incident-metrics'] })
    queryClient.invalidateQueries({ queryKey: ['incident-detail', incident.id] })
  }

  const updateMutation = useMutation({
    mutationFn: (body: IncidentUpdate) => incidentsApi.update(incident.id, body),
    onSuccess: (updated) => {
      addNotification({ type: 'success', title: `Incident INC-${updated.id} updated` })
      setAssignee(updated.assigned_to ?? '')
      invalidate()
    },
    onError: (error: unknown) => {
      addNotification({
        type: 'error',
        title: 'Could not update the incident',
        message: apiErrorMessage(error),
      })
    },
  })

  const noteMutation = useMutation({
    mutationFn: (note: { content: string; noteType: 'comment' | 'evidence' }) =>
      incidentsApi.addNote(incident.id, note.content, note.noteType),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['incident-detail', incident.id] })
    },
    onError: (error: unknown) => {
      addNotification({ type: 'error', title: 'Could not add the note', message: apiErrorMessage(error) })
    },
  })

  const trimmedAssignee = assignee.trim()
  const assigneeInvalid = trimmedAssignee !== '' && !isValidEmail(trimmedAssignee)
  const assigneeChanged = trimmedAssignee !== '' && trimmedAssignee !== (current.assigned_to ?? '')

  function handleAssign(event: FormEvent) {
    event.preventDefault()
    if (assigneeChanged && !assigneeInvalid && !updateMutation.isPending) {
      updateMutation.mutate({ assigned_to: trimmedAssignee })
    }
  }

  const statusOptions = reachableStatuses(current.status).map((value) => ({
    value,
    label: INCIDENT_STATUS_LABELS[value],
  }))
  const busy = updateMutation.isPending

  return (
    <>
      <SheetHeader className="space-y-2 border-b border-border p-4 pr-10">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-[11px] text-muted-foreground">INC-{current.id}</span>
          <SeverityPill severity={current.severity} />
          <IncidentStatusPill status={current.status} />
        </div>
        <SheetTitle className="text-[13px] leading-snug">{current.title}</SheetTitle>
        <SheetDescription>
          Opened by {current.created_by} on {formatDateTime(current.created_at)}
        </SheetDescription>
      </SheetHeader>

      <div className="flex-1 space-y-4 overflow-y-auto p-4">
        {writable && (
          <div className="space-y-3 rounded-lg border border-border p-4">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <span className="block text-[12px] font-medium">Status</span>
                <OptionSelect
                  label="Incident status"
                  value={current.status}
                  options={statusOptions}
                  disabled={busy || statusOptions.length < 2}
                  onChange={(status) => {
                    if (status !== current.status) updateMutation.mutate({ status })
                  }}
                  className="w-full"
                />
              </div>
              <div className="space-y-1">
                <span className="block text-[12px] font-medium">Severity</span>
                <OptionSelect
                  label="Incident severity"
                  value={current.severity}
                  options={SEVERITY_SELECT_OPTIONS}
                  disabled={busy}
                  onChange={(severity) => {
                    if (severity !== current.severity) updateMutation.mutate({ severity })
                  }}
                  className="w-full"
                />
              </div>
            </div>
            <p className="text-[11px] text-muted-foreground">
              Status only moves forward: new, investigating, contained, resolved, closed.
            </p>
            <form onSubmit={handleAssign} className="space-y-1">
              <Label htmlFor="incident-panel-assignee" className="text-[12px] font-medium">Assignee email</Label>
              <div className="flex items-center gap-2">
                <Input
                  id="incident-panel-assignee"
                  type="email"
                  maxLength={254}
                  value={assignee}
                  onChange={(e) => setAssignee(e.target.value)}
                  placeholder="analyst@example.com"
                  aria-invalid={assigneeInvalid}
                  className="h-8"
                />
                <Button
                  type="submit"
                  variant="outline"
                  className="h-8"
                  disabled={!assigneeChanged || assigneeInvalid || busy}
                >
                  Assign
                </Button>
                {current.assigned_to && (
                  <Button
                    type="button"
                    variant="ghost"
                    className="h-8"
                    disabled={busy}
                    onClick={() => updateMutation.mutate({ assigned_to: null })}
                  >
                    Unassign
                  </Button>
                )}
              </div>
              {assigneeInvalid && <p className="text-[11px] text-destructive">Enter a valid email address.</p>}
            </form>
          </div>
        )}

        <Tabs value={tab} onValueChange={setTab}>
          <TabsList>
            <TabsTrigger value="details">Details</TabsTrigger>
            <TabsTrigger value="timeline">Timeline{detail ? ` (${detail.notes.length})` : ''}</TabsTrigger>
            <TabsTrigger value="detections">
              Detections ({detail ? detail.detections.length : current.detection_ids.length})
            </TabsTrigger>
          </TabsList>

          <TabsContent value="details" className="space-y-3">
            {current.description && (
              <p className="whitespace-pre-wrap text-[12px] leading-relaxed text-foreground">{current.description}</p>
            )}
            <dl>
              <Row label="Assigned to">
                {current.assigned_to || <span className="text-muted-foreground">Unassigned</span>}
              </Row>
              <Row label="Priority">P{current.priority}</Row>
              <Row label="Hosts"><Chips values={current.hosts} /></Row>
              <Row label="Techniques"><Chips values={current.technique_ids} /></Row>
              <Row label="Tactics"><Chips values={current.tactic_ids} /></Row>
              <Row label="Open for">{detail ? formatDuration(detail.duration_seconds) : '—'}</Row>
              <Row label="Time to detect">{formatDuration(current.ttd_seconds)}</Row>
              <Row label="Time to resolve">{formatDuration(current.ttr_seconds)}</Row>
              <Row label="Updated">{formatDateTime(current.updated_at)}</Row>
              <Row label="Closed">{formatDateTime(current.closed_at)}</Row>
            </dl>
          </TabsContent>

          {(tab === 'timeline' || tab === 'detections') && detailQuery.isLoading && (
            <div className="mt-2 space-y-2" aria-label="Loading incident detail">
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
            </div>
          )}
          {(tab === 'timeline' || tab === 'detections') && detailQuery.isError && (
            <div className="mt-2">
              <ErrorCard
                title="Could not load the incident detail"
                message={apiErrorMessage(detailQuery.error)}
                onRetry={() => void detailQuery.refetch()}
              />
            </div>
          )}

          <TabsContent value="timeline">
            {detail && (
              <IncidentTimeline
                notes={detail.notes}
                writable={writable}
                pending={noteMutation.isPending}
                onAddNote={(content, noteType) => noteMutation.mutateAsync({ content, noteType })}
              />
            )}
          </TabsContent>

          <TabsContent value="detections">
            {detail && (
              <LinkedDetections
                detections={detail.detections}
                missing={Math.max(0, detail.detection_ids.length - detail.detections.length)}
              />
            )}
          </TabsContent>
        </Tabs>
      </div>
    </>
  )
}

/** Right-side detail panel for one incident: status, assignee, notes and linked detections. */
export function IncidentPanel({ incident, onClose }: IncidentPanelProps) {
  return (
    <Sheet open={incident !== null} onOpenChange={(next) => { if (!next) onClose() }}>
      <SheetContent side="right" className="flex w-full flex-col gap-0 bg-card p-0 sm:max-w-lg">
        {incident && <PanelBody key={incident.id} incident={incident} />}
      </SheetContent>
    </Sheet>
  )
}
