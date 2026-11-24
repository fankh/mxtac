import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { Button } from '@/components/ui/button'
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from '@/components/ui/dialog'
import { apiErrorMessage, rulesApi } from '@/lib/api'
import { useUIStore } from '@/stores/uiStore'
import type { Rule, RuleTestResult } from '@/types/api'
import { RuleTestPanel } from './RuleTestPanel'
import { parseSampleEvent } from './sigmaYaml'

interface RuleTestDialogProps {
  rule: Rule
  onClose: () => void
}

/** Evaluate a stored rule against a sample event (POST /rules/{id}/test). Mount only while open. */
export function RuleTestDialog({ rule, onClose }: RuleTestDialogProps) {
  const addNotification = useUIStore((s) => s.addNotification)
  const [sample, setSample] = useState('{}')
  const [sampleError, setSampleError] = useState('')
  const [result, setResult] = useState<RuleTestResult | null>(null)

  const testMutation = useMutation({
    mutationFn: (event: Record<string, unknown>) => rulesApi.test(rule.id, event),
    onSuccess: setResult,
    onError: (err: unknown) => {
      addNotification({ type: 'error', title: 'Test failed', message: apiErrorMessage(err, 'Could not test the rule') })
    },
  })

  const run = () => {
    setResult(null)
    const parsed = parseSampleEvent(sample)
    if ('error' in parsed) {
      setSampleError(parsed.error)
      return
    }
    setSampleError('')
    testMutation.mutate(parsed.event)
  }

  return (
    <Dialog open onOpenChange={(next) => { if (!next) onClose() }}>
      <DialogContent className="max-w-xl">
        <DialogHeader>
          <DialogTitle>Test rule</DialogTitle>
          <DialogDescription>{rule.title}</DialogDescription>
        </DialogHeader>
        <RuleTestPanel
          sample={sample}
          onSampleChange={(v) => { setSample(v); setSampleError(''); setResult(null) }}
          onRun={run}
          running={testMutation.isPending}
          inputError={sampleError}
          result={result}
          rows={10}
        />
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Close</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
