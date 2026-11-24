import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { Check, Copy, Send } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { apiErrorMessage, ingestApi } from '@/lib/api'
import { useUIStore } from '@/stores/uiStore'
import type { Connector } from '@/types/api'

interface IngestHelpCardProps {
  /** Generic webhook sources that can receive events. */
  sources: Connector[]
}

const SAMPLE_EVENT = { event_type: 'test', message: 'Test event from the MxTac console' }

function curlCommand(source: string): string {
  return [
    `curl -X POST ${window.location.origin}/api/v1/ingest \\`,
    `  -H "Content-Type: application/json" \\`,
    `  -H "X-MxTac-Source: ${source}" \\`,
    `  -H "X-MxTac-Token: <webhook token>" \\`,
    `  -d '${JSON.stringify(SAMPLE_EVENT)}'`,
  ].join('\n')
}

/** How to push events to POST /api/v1/ingest, with a one-click test for a generic webhook source. */
export function IngestHelpCard({ sources }: IngestHelpCardProps) {
  const addNotification = useUIStore((s) => s.addNotification)
  const [selected, setSelected] = useState('')
  const [token, setToken] = useState('')
  const [copied, setCopied] = useState(false)

  const source = sources.find((s) => s.name === selected)?.name ?? sources[0]?.name ?? ''
  const command = curlCommand(source || '<source name>')

  const sendMutation = useMutation({
    mutationFn: () => ingestApi.send(source, token.trim(), { ...SAMPLE_EVENT, sent_at: new Date().toISOString() }),
    onSuccess: (result) => {
      addNotification({
        type: result.accepted > 0 ? 'success' : 'warning',
        title: result.accepted > 0 ? 'Test event accepted' : 'Test event rejected',
        message: `${result.accepted} accepted, ${result.rejected} rejected by ${source}`,
      })
    },
    onError: (err: unknown) => {
      addNotification({
        type: 'error',
        title: 'Test event failed',
        message: apiErrorMessage(err, 'The ingest endpoint did not accept the event'),
      })
    },
  })

  const copyCommand = () => {
    navigator.clipboard.writeText(command).then(
      () => {
        setCopied(true)
        setTimeout(() => setCopied(false), 2000)
      },
      () => addNotification({ type: 'error', title: 'Copy failed', message: 'Select the command and copy it manually.' }),
    )
  }

  return (
    <Card>
      <CardContent className="space-y-3 p-4">
        <div>
          <h2 className="text-[12px] font-semibold text-foreground">Send a test event</h2>
          <p className="mt-1 text-[11px] text-muted-foreground">
            Any tool can push JSON to <code className="font-mono">POST /api/v1/ingest</code> as a generic webhook source.
            Send one object or an array of objects, up to 5 MB per request and 100 requests per minute per source.
            The response is 202 with the accepted and rejected counts.
          </p>
        </div>

        <div className="relative">
          <pre className="overflow-x-auto rounded-lg border border-border bg-muted p-3 pr-10 font-mono text-[11px] leading-relaxed text-foreground">
            {command}
          </pre>
          <Button
            variant="ghost"
            size="icon"
            title="Copy command"
            className="absolute right-1.5 top-1.5"
            onClick={copyCommand}
          >
            {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
          </Button>
        </div>

        {sources.length === 0 ? (
          <p className="text-[11px] text-muted-foreground">
            Add a generic webhook source first. Its name and webhook token are the credentials for this endpoint.
          </p>
        ) : (
          <form
            className="flex flex-wrap items-end gap-3"
            onSubmit={(e) => { e.preventDefault(); if (token.trim()) sendMutation.mutate() }}
          >
            {sources.length > 1 && (
              <div className="space-y-1.5">
                <Label className="text-[12px] font-medium">Source</Label>
                <Select value={source} onValueChange={setSelected}>
                  <SelectTrigger className="h-8 w-44" aria-label="Source"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {sources.map((s) => <SelectItem key={s.id} value={s.name}>{s.name}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
            )}
            <div className="min-w-[220px] flex-1 space-y-1.5">
              <Label htmlFor="ingest-token" className="text-[12px] font-medium">Webhook token for {source}</Label>
              <Input
                id="ingest-token"
                type="password"
                className="h-8"
                value={token}
                autoComplete="off"
                placeholder="Token set when the source was added"
                onChange={(e) => setToken(e.target.value)}
              />
            </div>
            <Button type="submit" size="lg" className="gap-1.5" disabled={!token.trim() || sendMutation.isPending}>
              <Send className="h-3.5 w-3.5" />
              {sendMutation.isPending ? 'Sending…' : 'Send test event'}
            </Button>
          </form>
        )}
      </CardContent>
    </Card>
  )
}
