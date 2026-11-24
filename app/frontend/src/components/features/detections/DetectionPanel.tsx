import { useState, type FormEvent, type ReactNode } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import type { Detection, DetectionStatus, DetectionUpdate } from '@/types/api'
import { apiErrorMessage, detectionsApi } from '@/lib/api'
import { useAuthStore } from '@/stores/authStore'
import { useUIStore } from '@/stores/uiStore'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@/components/ui/sheet'
import { ScoreCircle, SeverityPill } from '@/components/shared/SeverityBadge'
import { StatusPill } from '@/components/shared/StatusPill'
import { DETECTION_STATUS_LABELS } from './utils'
import { canWrite } from '@/lib/roles'
import { formatDateTime } from '@/lib/format'

interface DetectionPanelProps {
  /** Detection to show; the panel is closed while this is null. */
  detection: Detection | null
  onClose: () => void
  /** Called with the server copy after a successful change. */
  onUpdated?: (detection: Detection) => void
}

interface StatusAction {
  status: DetectionStatus
  label: string
}

/** Status changes offered for each current status; the first one is the primary button. */
const STATUS_ACTIONS: Record<DetectionStatus, StatusAction[]> = {
  active: [
    { status: 'investigating', label: 'Investigate' },
    { status: 'resolved', label: 'Resolve' },
    { status: 'false_positive', label: 'False positive' },
  ],
  investigating: [
    { status: 'resolved', label: 'Resolve' },
    { status: 'false_positive', label: 'False positive' },
    { status: 'active', label: 'Reopen' },
  ],
  resolved: [{ status: 'active', label: 'Reopen' }],
  false_positive: [{ status: 'active', label: 'Reopen' }],
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[110px_minmax(0,1fr)] gap-2 border-b border-border py-1.5 last:border-0">
      <dt className="text-[11px] font-medium text-muted-foreground">{label}</dt>
      <dd className="break-words text-[12px] text-foreground">{children}</dd>
    </div>
  )
}

function PanelBody({ detection, onUpdated }: { detection: Detection; onUpdated?: (d: Detection) => void }) {
  const queryClient = useQueryClient()
  const addNotification = useUIStore((s) => s.addNotification)
  const writable = canWrite(useAuthStore((s) => s.user?.role))
  const [assignee, setAssignee] = useState(detection.assigned_to ?? '')

  const mutation = useMutation({
    mutationFn: (body: DetectionUpdate) => detectionsApi.update(detection.id, body),
    onSuccess: (updated, body) => {
      addNotification({
        type: 'success',
        title: body.status
          ? `Detection set to ${DETECTION_STATUS_LABELS[body.status].toLowerCase()}`
          : `Detection assigned to ${body.assigned_to}`,
      })
      queryClient.invalidateQueries({ queryKey: ['detections'] })
      onUpdated?.(updated)
    },
    onError: (error: unknown) => {
      addNotification({
        type: 'error',
        title: 'Could not update the detection',
        message: apiErrorMessage(error),
      })
    },
  })

  const trimmedAssignee = assignee.trim()
  const assigneeChanged = trimmedAssignee !== '' && trimmedAssignee !== (detection.assigned_to ?? '')

  function handleAssign(event: FormEvent) {
    event.preventDefault()
    if (assigneeChanged && !mutation.isPending) mutation.mutate({ assigned_to: trimmedAssignee })
  }

  const related = detection.related_technique_ids ?? []

  return (
    <>
      <SheetHeader className="space-y-2 border-b border-border p-4 pr-10">
        <div className="flex items-start gap-3">
          <ScoreCircle score={detection.score} severity={detection.severity} />
          <div className="min-w-0 space-y-1">
            <SheetTitle className="text-[13px] leading-snug">{detection.name}</SheetTitle>
            <SheetDescription>
              {detection.technique_id} · {detection.tactic}
            </SheetDescription>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <SeverityPill severity={detection.severity} />
          <StatusPill status={detection.status} />
          {detection.confidence != null && (
            <span className="text-[11px] text-muted-foreground">Confidence {detection.confidence}%</span>
          )}
          {detection.cvss_v3 != null && (
            <span className="text-[11px] text-muted-foreground">CVSS {detection.cvss_v3}</span>
          )}
        </div>
      </SheetHeader>

      <div className="flex-1 space-y-4 overflow-y-auto p-4">
        {detection.description && (
          <p className="text-[12px] leading-relaxed text-foreground">{detection.description}</p>
        )}

        <dl>
          <Row label="Technique">
            <span className="font-mono">{detection.technique_id}</span> {detection.technique_name}
          </Row>
          <Row label="Tactic">
            {detection.tactic}
            {detection.tactic_id && <span className="text-muted-foreground"> ({detection.tactic_id})</span>}
          </Row>
          <Row label="Host">{detection.host}</Row>
          {detection.user && <Row label="User">{detection.user}</Row>}
          {detection.process && (
            <Row label="Process">
              <code className="break-all rounded bg-muted px-1 font-mono text-[11px]">{detection.process}</code>
            </Row>
          )}
          {detection.log_source && <Row label="Log source">{detection.log_source}</Row>}
          {detection.event_id && (
            <Row label="Event ID">
              <span className="font-mono">{detection.event_id}</span>
            </Row>
          )}
          {detection.rule_name && <Row label="Rule">{detection.rule_name}</Row>}
          {detection.occurrence_count != null && (
            <Row label="Occurrences">{detection.occurrence_count.toLocaleString('en-US')}</Row>
          )}
          {detection.priority && <Row label="Priority">{detection.priority}</Row>}
          <Row label="Assigned to">
            {detection.assigned_to || <span className="text-muted-foreground">Unassigned</span>}
          </Row>
          <Row label="Time">{formatDateTime(detection.time)}</Row>
          <Row label="Detection ID">
            <span className="font-mono">{detection.id}</span>
          </Row>
        </dl>

        {related.length > 0 && (
          <div className="space-y-1.5">
            <h3 className="text-[12px] font-semibold">Related techniques</h3>
            <div className="flex flex-wrap gap-1">
              {related.map((technique) => (
                <span
                  key={technique}
                  className="rounded border border-border bg-muted px-1.5 py-0.5 font-mono text-[11px] text-foreground"
                >
                  {technique}
                </span>
              ))}
            </div>
          </div>
        )}

        {writable && (
          <form onSubmit={handleAssign} className="space-y-1">
            <Label htmlFor="detection-assignee" className="text-[12px] font-medium">Assign to</Label>
            <div className="flex items-center gap-2">
              <Input
                id="detection-assignee"
                maxLength={255}
                value={assignee}
                onChange={(e) => setAssignee(e.target.value)}
                placeholder="Email or username"
                className="h-8"
              />
              <Button type="submit" variant="outline" className="h-8" disabled={!assigneeChanged || mutation.isPending}>
                Assign
              </Button>
            </div>
          </form>
        )}
      </div>

      {writable && (
        <div className="flex flex-wrap items-center gap-2 border-t border-border p-4">
          {(STATUS_ACTIONS[detection.status] ?? []).map((action, index) => (
            <Button
              key={action.status}
              variant={index === 0 ? 'default' : 'outline'}
              disabled={mutation.isPending}
              onClick={() => mutation.mutate({ status: action.status })}
            >
              {action.label}
            </Button>
          ))}
        </div>
      )}
    </>
  )
}

/** Right-side detail panel for one detection, with status and assignee changes. */
export function DetectionPanel({ detection, onClose, onUpdated }: DetectionPanelProps) {
  return (
    <Sheet open={detection !== null} onOpenChange={(next) => { if (!next) onClose() }}>
      <SheetContent side="right" className="flex w-full flex-col gap-0 bg-card p-0 sm:max-w-md">
        {detection && <PanelBody key={detection.id} detection={detection} onUpdated={onUpdated} />}
      </SheetContent>
    </Sheet>
  )
}
