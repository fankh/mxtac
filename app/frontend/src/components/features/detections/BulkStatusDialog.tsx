import type { DetectionStatus } from '@/types/api'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { DETECTION_STATUS_LABELS, plural } from './utils'

interface BulkStatusDialogProps {
  /** Status to apply; the dialog is open while this is set. */
  status: DetectionStatus | null
  count: number
  pending: boolean
  onConfirm: () => void
  onClose: () => void
}

/** Confirmation step before POST /detections/bulk. */
export function BulkStatusDialog({ status, count, pending, onConfirm, onClose }: BulkStatusDialogProps) {
  return (
    <Dialog open={status !== null} onOpenChange={(next) => { if (!next) onClose() }}>
      <DialogContent className="max-w-sm">
        <DialogHeader>
          <DialogTitle>Change status</DialogTitle>
          <DialogDescription>
            {status &&
              `Set ${plural(count, 'detection')} to ${DETECTION_STATUS_LABELS[status].toLowerCase()}?`}
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={pending}>
            Cancel
          </Button>
          <Button onClick={onConfirm} disabled={pending}>
            {pending ? 'Updating…' : 'Confirm'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
