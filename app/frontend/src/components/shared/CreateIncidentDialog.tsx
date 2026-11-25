import { useEffect, useState, type FormEvent } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import type { Incident, IncidentCreate, SeverityLevel } from '@/types/api'
import { apiErrorMessage, incidentsApi } from '@/lib/api'
import { useUIStore } from '@/stores/uiStore'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { OptionSelect } from '@/components/shared/OptionSelect'
import { SEVERITY_LABELS, SEVERITY_OPTIONS } from '@/lib/severity'
import { isValidEmail, plural } from '@/lib/format'

interface CreateIncidentDialogProps {
  open: boolean
  onClose: () => void
  /**
   * Detections to link. When given, the dialog links exactly these and hides
   * the manual ID field.
   */
  detectionIds?: string[]
  defaultSeverity?: SeverityLevel
  onCreated?: (incident: Incident) => void
}

const SEVERITY_SELECT_OPTIONS = SEVERITY_OPTIONS.map((value) => ({ value, label: SEVERITY_LABELS[value] }))

/** Centered form for POST /incidents. */
export function CreateIncidentDialog({
  open,
  onClose,
  detectionIds,
  defaultSeverity = 'medium',
  onCreated,
}: CreateIncidentDialogProps) {
  const queryClient = useQueryClient()
  const addNotification = useUIStore((s) => s.addNotification)

  const [title, setTitle] = useState('')
  const [severity, setSeverity] = useState<SeverityLevel>(defaultSeverity)
  const [description, setDescription] = useState('')
  const [assignee, setAssignee] = useState('')
  const [manualIds, setManualIds] = useState('')

  // Start from a blank form every time the dialog opens.
  useEffect(() => {
    if (!open) return
    setTitle('')
    setSeverity(defaultSeverity)
    setDescription('')
    setAssignee('')
    setManualIds('')
  }, [open, defaultSeverity])

  const mutation = useMutation({
    mutationFn: (body: IncidentCreate) => incidentsApi.create(body),
    onSuccess: (incident) => {
      addNotification({
        type: 'success',
        title: `Incident INC-${incident.id} created`,
        message:
          incident.detection_ids.length > 0
            ? `${plural(incident.detection_ids.length, 'detection')} linked.`
            : undefined,
      })
      queryClient.invalidateQueries({ queryKey: ['incidents'] })
      queryClient.invalidateQueries({ queryKey: ['incident-metrics'] })
      onCreated?.(incident)
      onClose()
    },
    onError: (error: unknown) => {
      addNotification({
        type: 'error',
        title: 'Could not create the incident',
        message: apiErrorMessage(error),
      })
    },
  })

  const linkedIds =
    detectionIds ??
    manualIds
      .split(/[\s,]+/)
      .map((id) => id.trim())
      .filter(Boolean)
  const trimmedTitle = title.trim()
  const trimmedAssignee = assignee.trim()
  const assigneeInvalid = trimmedAssignee !== '' && !isValidEmail(trimmedAssignee)
  const canSubmit = trimmedTitle !== '' && !assigneeInvalid && !mutation.isPending

  function handleSubmit(event: FormEvent) {
    event.preventDefault()
    if (!canSubmit) return
    mutation.mutate({
      title: trimmedTitle,
      severity,
      description: description.trim() || null,
      assigned_to: trimmedAssignee || null,
      detection_ids: [...new Set(linkedIds)],
    })
  }

  return (
    <Dialog open={open} onOpenChange={(next) => { if (!next) onClose() }}>
      <DialogContent className="max-w-md">
        <form onSubmit={handleSubmit} className="space-y-3">
          <DialogHeader>
            <DialogTitle>Create incident</DialogTitle>
            <DialogDescription>
              {detectionIds
                ? `${plural(detectionIds.length, 'selected detection')} will be linked to the new incident.`
                : 'Open an incident to track an investigation.'}
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-1">
            <Label htmlFor="incident-title" className="text-[12px] font-medium">Title</Label>
            <Input
              id="incident-title"
              required
              maxLength={500}
              autoFocus
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Lateral movement on the finance subnet"
              className="h-8"
            />
          </div>

          <div className="space-y-1">
            <span className="block text-[12px] font-medium">Severity</span>
            <OptionSelect
              label="Incident severity"
              value={severity}
              options={SEVERITY_SELECT_OPTIONS}
              onChange={setSeverity}
              className="w-full"
            />
          </div>

          <div className="space-y-1">
            <Label htmlFor="incident-description" className="text-[12px] font-medium">Description</Label>
            <Textarea
              id="incident-description"
              rows={3}
              maxLength={10000}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="What happened and what is known so far"
            />
          </div>

          <div className="space-y-1">
            <Label htmlFor="incident-assignee" className="text-[12px] font-medium">Assignee email</Label>
            <Input
              id="incident-assignee"
              type="email"
              maxLength={254}
              value={assignee}
              onChange={(e) => setAssignee(e.target.value)}
              placeholder="analyst@example.com"
              aria-invalid={assigneeInvalid}
              className="h-8"
            />
            {assigneeInvalid && (
              <p className="text-[11px] text-destructive">Enter a valid email address.</p>
            )}
          </div>

          {!detectionIds && (
            <div className="space-y-1">
              <Label htmlFor="incident-detections" className="text-[12px] font-medium">Detection IDs</Label>
              <Input
                id="incident-detections"
                value={manualIds}
                onChange={(e) => setManualIds(e.target.value)}
                placeholder="Comma-separated, optional"
                className="h-8"
              />
              <p className="text-[11px] text-muted-foreground">
                Hosts, techniques and tactics are filled in from the linked detections.
              </p>
            </div>
          )}

          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={!canSubmit}>
              {mutation.isPending ? 'Creating…' : 'Create incident'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
