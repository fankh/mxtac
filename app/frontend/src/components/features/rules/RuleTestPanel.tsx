import { CircleAlert, CircleCheck, CircleMinus, FlaskConical } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { cn } from '@/lib/utils'
import type { RuleTestResult } from '@/types/api'

interface RuleTestPanelProps {
  sample: string
  onSampleChange: (value: string) => void
  onRun: () => void
  running: boolean
  /** Problem found before the request was sent, such as invalid JSON. */
  inputError?: string
  result: RuleTestResult | null
  rows?: number
}

/** Sample event box, a Run button and the outcome of POST /rules/test or /rules/{id}/test. */
export function RuleTestPanel({ sample, onSampleChange, onRun, running, inputError, result, rows = 5 }: RuleTestPanelProps) {
  return (
    <div className="space-y-2">
      <div className="flex items-end justify-between gap-2">
        <div>
          <Label htmlFor="rule-sample-event" className="text-[12px] font-medium">Sample event (JSON)</Label>
          <p className="text-[11px] text-muted-foreground">The rule is evaluated against this one event. Nothing is saved.</p>
        </div>
        <Button type="button" variant="outline" className="gap-1.5" onClick={onRun} disabled={running}>
          <FlaskConical className="h-3.5 w-3.5" />
          {running ? 'Testing…' : 'Run test'}
        </Button>
      </div>
      <Textarea
        id="rule-sample-event"
        rows={rows}
        spellCheck={false}
        className="font-mono text-[11px]"
        value={sample}
        onChange={(e) => onSampleChange(e.target.value)}
      />
      {inputError && <p role="alert" className="text-[11px] text-destructive">{inputError}</p>}
      {result && <RuleTestOutcome result={result} />}
    </div>
  )
}

function RuleTestOutcome({ result }: { result: RuleTestResult }) {
  const failed = result.errors.length > 0
  const Icon = failed ? CircleAlert : result.matched ? CircleCheck : CircleMinus
  const label = failed ? 'Rule error' : result.matched ? 'Matched' : 'No match'
  return (
    <div
      role="status"
      className={cn(
        'flex items-start gap-2 rounded-md border px-3 py-2 text-[11px]',
        failed ? 'sev-critical' : result.matched ? 'status-green' : 'sev-info',
      )}
    >
      <Icon className="mt-px h-3.5 w-3.5 shrink-0" />
      <div>
        <p className="font-medium">{label}</p>
        {failed
          ? <ul className="mt-0.5 space-y-0.5">{result.errors.map((e) => <li key={e}>{e}</li>)}</ul>
          : <p>{result.matched ? 'The sample event triggers this rule.' : 'The sample event does not trigger this rule.'}</p>}
      </div>
    </div>
  )
}
