import { useState, type ChangeEvent } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Button } from '@/components/ui/button'
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { apiErrorMessage, rulesApi } from '@/lib/api'
import { useUIStore } from '@/stores/uiStore'

/** Backend limit for POST /rules/import (10 MB of YAML). */
const MAX_IMPORT_CHARS = 10_000_000

interface RuleImportDialogProps {
  onClose: () => void
}

/** Bulk import: paste YAML or pick .yml files; several rules are separated by `---`. Mount only while open. */
export function RuleImportDialog({ onClose }: RuleImportDialogProps) {
  const queryClient = useQueryClient()
  const addNotification = useUIStore((s) => s.addNotification)
  const [yaml, setYaml] = useState('')
  const [error, setError] = useState('')

  const importMutation = useMutation({
    mutationFn: () => rulesApi.import(yaml),
    onSuccess: (result) => {
      if (result.imported === 0) {
        setError('No valid Sigma rules were found in this YAML.')
        return
      }
      queryClient.invalidateQueries({ queryKey: ['rules'] })
      queryClient.invalidateQueries({ queryKey: ['rules-stats'] })
      addNotification({
        type: 'success',
        title: `Imported ${result.imported} ${result.imported === 1 ? 'rule' : 'rules'}`,
        message: `${result.total_rules} rules in total`,
      })
      onClose()
    },
    onError: (err: unknown) => {
      const message = apiErrorMessage(err, 'Could not import the rules')
      setError(message)
      addNotification({ type: 'error', title: 'Import failed', message })
    },
  })

  const handleFiles = async (e: ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(e.target.files ?? [])
    e.target.value = ''
    if (files.length === 0) return
    try {
      const texts = await Promise.all(files.map((f) => f.text()))
      setYaml(texts.map((t) => t.trim()).filter(Boolean).join('\n---\n'))
      setError('')
    } catch {
      setError('Could not read the selected files.')
    }
  }

  const handleImport = () => {
    if (!yaml.trim()) {
      setError('Paste Sigma YAML or choose a file first.')
      return
    }
    if (yaml.length > MAX_IMPORT_CHARS) {
      setError('The YAML is larger than the 10 MB import limit.')
      return
    }
    setError('')
    importMutation.mutate()
  }

  return (
    <Dialog open onOpenChange={(next) => { if (!next) onClose() }}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>Import Sigma rules</DialogTitle>
          <DialogDescription>
            Paste one or more rules, or choose YAML files. Separate several rules with a line of three dashes.
            Documents that are not valid Sigma rules are skipped.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-3">
          <div className="space-y-1.5">
            <Label htmlFor="rule-import-files" className="text-[12px] font-medium">YAML files</Label>
            <Input id="rule-import-files" type="file" accept=".yml,.yaml" multiple onChange={handleFiles} />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="rule-import-yaml" className="text-[12px] font-medium">YAML</Label>
            <Textarea
              id="rule-import-yaml"
              rows={14}
              spellCheck={false}
              className="font-mono text-[11px]"
              placeholder={'title: My rule\nlogsource:\n  product: windows\ndetection:\n  selection:\n    EventID: 4625\n  condition: selection\nlevel: medium'}
              value={yaml}
              onChange={(e) => { setYaml(e.target.value); setError('') }}
            />
          </div>
          {error && <p role="alert" className="rounded-md border sev-critical px-3 py-2 text-[11px]">{error}</p>}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={importMutation.isPending}>Cancel</Button>
          <Button onClick={handleImport} disabled={importMutation.isPending}>
            {importMutation.isPending ? 'Importing…' : 'Import'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
