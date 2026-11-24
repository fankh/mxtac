import { useState, useEffect } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import type { Detection, DetectionUpdate } from '../../../types/api'
import { detectionsApi } from '../../../lib/api'
import { ScoreCircle, SeverityPill } from '../../shared/SeverityBadge'
import { StatusPill } from '../../shared/StatusPill'

interface Props {
  detection: Detection | null
  onClose: () => void
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[120px_1fr] gap-2 py-[5px] border-b border-border">
      <span className="text-[10px] font-medium text-muted-foreground uppercase">{label}</span>
      <span className="text-[11px] text-foreground break-words">{value}</span>
    </div>
  )
}

export function DetectionPanel({ detection, onClose }: Props) {
  const [assignMode, setAssignMode] = useState(false)
  const [assignInput, setAssignInput] = useState('')

  const queryClient = useQueryClient()

  // Reset assign state when the selected detection changes
  useEffect(() => {
    setAssignMode(false)
    setAssignInput('')
  }, [detection?.id])

  const mutation = useMutation({
    mutationFn: (body: DetectionUpdate) => detectionsApi.update(detection!.id, body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['detections'] })
      onClose()
    },
  })

  if (!detection) return null

  const isUpdating = mutation.isPending

  function handleAssignConfirm() {
    if (assignInput.trim()) {
      mutation.mutate({ assigned_to: assignInput.trim() })
    }
  }

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 z-30 bg-transparent"
        onClick={onClose}
      />

      {/* Panel */}
      <div className="fixed top-[46px] right-0 bottom-0 w-[436px] bg-card shadow-xl z-40 flex flex-col overflow-hidden border-l border-border">
        {/* Header */}
        <div className="flex items-start justify-between px-4 py-3 border-b border-border">
          <div className="flex items-start gap-3 min-w-0">
            <ScoreCircle score={detection.score} severity={detection.severity} />
            <div className="min-w-0">
              <h2 className="text-[13px] font-semibold text-foreground leading-snug">{detection.name}</h2>
              <p className="text-[11px] text-muted-foreground mt-[2px]">{detection.technique_id} · {detection.tactic}</p>
            </div>
          </div>
          <button
            className="text-muted-foreground hover:text-foreground ml-2 text-lg leading-none"
            onClick={onClose}
            title="Close"
          >
            ×
          </button>
        </div>

        {/* Score badges row */}
        <div className="flex items-center gap-3 px-4 py-2 border-b border-border">
          <SeverityPill severity={detection.severity} />
          <StatusPill status={detection.status} />
          {detection.confidence !== undefined && (
            <span className="text-[10px] text-muted-foreground">Confidence: {detection.confidence}%</span>
          )}
          {detection.cvss_v3 !== undefined && (
            <span className="text-[10px] text-muted-foreground">CVSS: {detection.cvss_v3}</span>
          )}
        </div>

        {/* Scrollable body */}
        <div className="flex-1 overflow-y-auto px-4 py-2">
          {detection.description && (
            <p className="text-[11px] text-foreground/80 mb-3 leading-relaxed">{detection.description}</p>
          )}

          <div className="mb-2">
            <Row label="Technique" value={`${detection.technique_id} – ${detection.technique_name}`} />
            <Row label="Tactic" value={detection.tactic} />
            <Row label="Host" value={detection.host} />
            {detection.user && <Row label="User" value={detection.user} />}
            {detection.process && <Row label="Process" value={<code className="text-[10px] bg-background px-1 rounded">{detection.process}</code>} />}
            {detection.log_source && <Row label="Log Source" value={detection.log_source} />}
            {detection.event_id && <Row label="Event ID" value={detection.event_id} />}
            {detection.rule_name && <Row label="Sigma Rule" value={detection.rule_name} />}
            {detection.occurrence_count !== undefined && (
              <Row label="Occurrences" value={detection.occurrence_count.toLocaleString()} />
            )}
            {detection.assigned_to && <Row label="Assigned To" value={detection.assigned_to} />}
            <Row label="Time" value={new Date(detection.time).toLocaleString()} />
          </div>

          {detection.related_technique_ids && detection.related_technique_ids.length > 0 && (
            <div className="mt-3">
              <p className="text-[10px] font-medium text-muted-foreground uppercase mb-1">Related Techniques</p>
              <div className="flex flex-wrap gap-1">
                {detection.related_technique_ids.map((t) => (
                  <span key={t} className="text-[10px] bg-background border border-border rounded px-2 py-[2px] text-foreground/80">{t}</span>
                ))}
              </div>
            </div>
          )}

          {mutation.isError && (
            <p className="mt-3 text-[11px] text-crit-text">Update failed. Please try again.</p>
          )}
        </div>

        {/* Assign input row (shown when assign mode is active) */}
        {assignMode && (
          <div className="border-t border-border px-4 py-2 flex items-center gap-2">
            <input
              autoFocus
              type="text"
              placeholder="Assign to (email or username)"
              value={assignInput}
              onChange={(e) => setAssignInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && assignInput.trim()) handleAssignConfirm()
                if (e.key === 'Escape') { setAssignMode(false); setAssignInput('') }
              }}
              className="flex-1 h-[28px] px-2 text-[11px] border border-border rounded-md bg-background text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-primary"
            />
            <button
              onClick={handleAssignConfirm}
              disabled={!assignInput.trim() || isUpdating}
              className="h-[28px] px-3 text-[11px] bg-primary text-white rounded-md hover:opacity-90 disabled:opacity-50"
            >
              Confirm
            </button>
            <button
              onClick={() => { setAssignMode(false); setAssignInput('') }}
              className="text-[11px] text-muted-foreground hover:text-foreground"
            >
              Cancel
            </button>
          </div>
        )}

        {/* Action footer */}
        <div className="border-t border-border px-4 py-3 flex items-center gap-2">
          <button
            onClick={() => mutation.mutate({ status: 'investigating' })}
            disabled={isUpdating}
            className="flex-1 h-[30px] bg-primary text-white text-[12px] font-medium rounded-md hover:opacity-90 transition-opacity disabled:opacity-50"
          >
            Investigate
          </button>
          <button
            onClick={() => setAssignMode((v) => !v)}
            disabled={isUpdating}
            className="h-[30px] px-3 border border-border text-[12px] text-foreground/80 rounded-md hover:bg-background transition-colors disabled:opacity-50"
          >
            Assign
          </button>
          <button
            onClick={() => mutation.mutate({ status: 'resolved' })}
            disabled={isUpdating}
            className="h-[30px] px-3 border border-border text-[12px] text-foreground/80 rounded-md hover:bg-background transition-colors disabled:opacity-50"
          >
            Resolve
          </button>
          <button
            onClick={() => mutation.mutate({ status: 'false_positive' })}
            disabled={isUpdating}
            className="h-[30px] px-3 border border-border text-[12px] text-muted-foreground rounded-md hover:bg-background transition-colors disabled:opacity-50"
          >
            FP
          </button>
        </div>
      </div>
    </>
  )
}
