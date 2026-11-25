import { useCallback, useEffect, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import Editor, { type OnMount } from '@monaco-editor/react'
import { RefreshCw } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from '@/components/ui/dialog'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import { apiErrorMessage, rulesApi } from '@/lib/api'
import { useUIStore } from '@/stores/uiStore'
import { cn } from '@/lib/utils'
import type { RuleTestResult } from '@/types/api'
import { RuleTestPanel } from './RuleTestPanel'
import {
  EXAMPLE_EVENT, EXAMPLE_SIGMA, checkSigmaYaml, formatYaml, parseSampleEvent, yamlSyntaxProblem,
} from './sigmaYaml'

type CodeEditor = Parameters<OnMount>[0]
type Monaco = Parameters<OnMount>[1]

/** Editor height: 360px where there is room, down to 240px on a short phone screen. */
const EDITOR_HEIGHT = 'h-[clamp(240px,45dvh,360px)]'

interface RuleEditorDialogProps {
  /** The rule to edit; null opens an empty editor for a new rule. */
  ruleId: string | null
  /** Without write access the rule is shown read-only and can still be tested. */
  canWrite: boolean
  onClose: () => void
}

/** Create or edit a Sigma rule in the Monaco YAML editor. Mount it only while it is open. */
export function RuleEditorDialog({ ruleId, canWrite, onClose }: RuleEditorDialogProps) {
  const queryClient = useQueryClient()
  const theme = useUIStore((s) => s.theme)
  const addNotification = useUIStore((s) => s.addNotification)
  const editorRef = useRef<CodeEditor | null>(null)
  const monacoRef = useRef<Monaco | null>(null)

  const creating = ruleId === null
  const [yaml, setYaml] = useState(creating ? EXAMPLE_SIGMA : '')
  const [enabled, setEnabled] = useState(true)
  const [errors, setErrors] = useState<string[]>([])
  const [sample, setSample] = useState(creating ? EXAMPLE_EVENT : '{}')
  const [sampleError, setSampleError] = useState('')
  const [testResult, setTestResult] = useState<RuleTestResult | null>(null)

  const detail = useQuery({
    queryKey: ['rule', ruleId],
    queryFn: () => rulesApi.get(ruleId ?? ''),
    enabled: !creating,
  })

  // Load the stored YAML once when an existing rule arrives.
  const loadedRef = useRef(false)
  useEffect(() => {
    if (detail.data && !loadedRef.current) {
      loadedRef.current = true
      setYaml(detail.data.content)
    }
  }, [detail.data])

  /** Show (or clear) a syntax error marker in the editor gutter. */
  const markSyntax = useCallback((text: string) => {
    const monaco = monacoRef.current
    const model = editorRef.current?.getModel()
    if (!monaco || !model) return
    const problem = yamlSyntaxProblem(text)
    if (!problem || problem.line === undefined) {
      monaco.editor.setModelMarkers(model, 'yaml', [])
      return
    }
    const column = (problem.column ?? 0) + 1
    monaco.editor.setModelMarkers(model, 'yaml', [{
      startLineNumber: problem.line + 1,
      endLineNumber: problem.line + 1,
      startColumn: column,
      endColumn: column + 1,
      message: problem.message,
      severity: monaco.MarkerSeverity.Error,
    }])
  }, [])

  const handleMount: OnMount = useCallback((editor, monaco) => {
    editorRef.current = editor
    monacoRef.current = monaco
  }, [])

  const handleChange = (value: string | undefined) => {
    const text = value ?? ''
    setYaml(text)
    setErrors([])
    setTestResult(null)
    markSyntax(text)
  }

  const saveMutation = useMutation({
    mutationFn: (title: string) =>
      ruleId === null
        ? rulesApi.create({ title, content: yaml, enabled })
        : rulesApi.update(ruleId, { content: yaml }),
    onSuccess: (rule) => {
      queryClient.invalidateQueries({ queryKey: ['rules'] })
      queryClient.invalidateQueries({ queryKey: ['rules-stats'] })
      if (ruleId !== null) queryClient.removeQueries({ queryKey: ['rule', ruleId] })
      addNotification({ type: 'success', title: creating ? 'Rule created' : 'Rule saved', message: rule.title })
      onClose()
    },
    onError: (err: unknown) => {
      const message = apiErrorMessage(err, 'Could not save the rule')
      setErrors([message])
      addNotification({ type: 'error', title: 'Save failed', message })
    },
  })

  const testMutation = useMutation({
    mutationFn: (event: Record<string, unknown>) => rulesApi.testContent(yaml, event),
    onSuccess: setTestResult,
    onError: (err: unknown) => {
      const message = apiErrorMessage(err, 'Could not test the rule')
      setTestResult({ matched: false, errors: [message] })
      addNotification({ type: 'error', title: 'Test failed', message })
    },
  })

  const handleSave = () => {
    const check = checkSigmaYaml(yaml)
    setErrors(check.errors)
    if (check.errors.length > 0 || !check.title) return
    saveMutation.mutate(check.title)
  }

  const handleTest = () => {
    setTestResult(null)
    const parsed = parseSampleEvent(sample)
    if ('error' in parsed) {
      setSampleError(parsed.error)
      return
    }
    setSampleError('')
    testMutation.mutate(parsed.event)
  }

  const handleFormat = () => {
    const formatted = formatYaml(yaml)
    setYaml(formatted)
    markSyntax(formatted)
  }

  const loading = !creating && detail.isLoading
  const loadFailed = !creating && detail.isError
  const title = creating ? 'New Sigma rule' : canWrite ? 'Edit rule' : 'View rule'

  return (
    <Dialog open onOpenChange={(next) => { if (!next) onClose() }}>
      <DialogContent className="max-w-4xl">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>
            {creating
              ? 'Write the rule in Sigma YAML. It needs a title and a detection block with a condition.'
              : detail.data?.title ?? 'Sigma YAML'}
          </DialogDescription>
        </DialogHeader>

        {loading && (
          <div className="space-y-2" aria-label="Loading rule">
            <Skeleton className={cn(EDITOR_HEIGHT, 'w-full')} />
            <Skeleton className="h-8 w-1/2" />
          </div>
        )}

        {loadFailed && (
          <div className="flex flex-col items-center gap-3 rounded-lg border border-border p-8 text-center">
            <p className="text-[12px] text-destructive">Could not load this rule.</p>
            <Button variant="outline" className="gap-1.5" onClick={() => detail.refetch()}>
              <RefreshCw className="h-3.5 w-3.5" />
              Retry
            </Button>
          </div>
        )}

        {!loading && !loadFailed && (
          <div className="space-y-3">
            <div className={cn(EDITOR_HEIGHT, 'overflow-hidden rounded-lg border border-border')}>
              <Editor
                height="100%"
                defaultLanguage="yaml"
                value={yaml}
                onChange={handleChange}
                onMount={handleMount}
                theme={theme === 'light' ? 'vs' : 'vs-dark'}
                loading={<Skeleton className="h-full w-full" />}
                options={{
                  readOnly: !canWrite,
                  minimap: { enabled: false },
                  fontSize: 12,
                  lineNumbers: 'on',
                  scrollBeyondLastLine: false,
                  wordWrap: 'on',
                  automaticLayout: true,
                  tabSize: 2,
                  padding: { top: 8, bottom: 8 },
                }}
              />
            </div>

            {errors.length > 0 && (
              <ul role="alert" className="space-y-0.5 rounded-md border sev-critical px-3 py-2 text-[11px]">
                {errors.map((e) => <li key={e}>{e}</li>)}
              </ul>
            )}

            <RuleTestPanel
              sample={sample}
              onSampleChange={(v) => { setSample(v); setSampleError(''); setTestResult(null) }}
              onRun={handleTest}
              running={testMutation.isPending}
              inputError={sampleError}
              result={testResult}
            />
          </div>
        )}

        <DialogFooter className="flex-col gap-3 sm:items-center sm:justify-between">
          <div className="flex flex-wrap items-center gap-3">
            {canWrite && !loading && !loadFailed && (
              <Button type="button" variant="outline" onClick={handleFormat} title="Re-indent the YAML">Format</Button>
            )}
            {canWrite && creating && (
              <div className="flex items-center gap-2">
                <Switch id="rule-enabled" checked={enabled} onCheckedChange={setEnabled} />
                <Label htmlFor="rule-enabled" className="text-[12px] font-medium">Enable after saving</Label>
              </div>
            )}
          </div>
          <div className="flex items-center justify-end gap-2">
            <Button type="button" variant="outline" onClick={onClose} disabled={saveMutation.isPending}>
              {canWrite ? 'Cancel' : 'Close'}
            </Button>
            {canWrite && (
              <Button type="button" onClick={handleSave} disabled={loading || loadFailed || saveMutation.isPending}>
                {saveMutation.isPending ? 'Saving…' : creating ? 'Create rule' : 'Save rule'}
              </Button>
            )}
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
