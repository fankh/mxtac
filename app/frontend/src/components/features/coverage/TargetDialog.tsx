import { useEffect, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Button } from '@/components/ui/button'
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { apiErrorMessage, coverageApi } from '@/lib/api'
import { useUIStore } from '@/stores/uiStore'
import type { CoverageTarget } from '@/types/api'

interface Props {
  open: boolean
  onOpenChange: (open: boolean) => void
  target: CoverageTarget | undefined
}

/** Edit the coverage target (PUT /coverage/target). */
export function TargetDialog({ open, onOpenChange, target }: Props) {
  const qc = useQueryClient()
  const addNotification = useUIStore((s) => s.addNotification)
  const [pct, setPct] = useState('80')
  const [enabled, setEnabled] = useState(true)
  const [label, setLabel] = useState('')

  // Reset the form from the stored target each time the dialog opens or closes.
  useEffect(() => {
    setPct(String(target?.target_pct ?? 80))
    setEnabled(target?.enabled ?? true)
    setLabel(target?.label ?? '')
  }, [open, target])

  const value = Number(pct)
  const valid = pct.trim() !== '' && Number.isFinite(value) && value >= 0 && value <= 100

  const mutation = useMutation({
    mutationFn: () => coverageApi.updateTarget({ target_pct: value, enabled, label: label.trim() || null }),
    onSuccess: (saved) => {
      qc.setQueryData(['coverage', 'target'], saved)
      addNotification({ type: 'success', title: 'Coverage target saved' })
      onOpenChange(false)
    },
    onError: (e: unknown) => {
      addNotification({
        type: 'error',
        title: 'Could not save the coverage target',
        message: apiErrorMessage(e),
      })
    },
  })

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-sm">
        <form
          className="grid grid-cols-1 gap-3"
          onSubmit={(e) => { e.preventDefault(); if (valid && !mutation.isPending) mutation.mutate() }}
        >
          <DialogHeader>
            <DialogTitle>Coverage target</DialogTitle>
            <DialogDescription>The share of in-scope techniques that enabled rules should cover.</DialogDescription>
          </DialogHeader>
          <div className="space-y-1.5">
            <Label htmlFor="coverage-target-pct" className="text-[12px] font-medium">Target (%)</Label>
            <Input
              id="coverage-target-pct"
              type="number"
              min={0}
              max={100}
              step="0.1"
              value={pct}
              onChange={(e) => setPct(e.target.value)}
              autoFocus
            />
            {!valid && <p className="text-[11px] text-destructive">Enter a number from 0 to 100.</p>}
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="coverage-target-label" className="text-[12px] font-medium">Label</Label>
            <Input
              id="coverage-target-label"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="Optional, for example Q1 goal"
              maxLength={100}
            />
          </div>
          <div className="flex items-center justify-between gap-3">
            <div>
              <Label htmlFor="coverage-target-enabled" className="text-[12px] font-medium">Flag when below target</Label>
              <p className="mt-1 text-[11px] text-muted-foreground">Marks coverage as below target on this page.</p>
            </div>
            <Switch id="coverage-target-enabled" checked={enabled} onCheckedChange={setEnabled} />
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
            <Button type="submit" disabled={!valid || mutation.isPending}>
              {mutation.isPending ? 'Saving…' : 'Save target'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
