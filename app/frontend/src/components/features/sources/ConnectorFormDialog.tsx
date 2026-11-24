import { useState, type FormEvent } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Wand2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { apiErrorMessage, connectorsApi } from '@/lib/api'
import { cn } from '@/lib/utils'
import { useUIStore } from '@/stores/uiStore'
import type { Connector, ConnectorType } from '@/types/api'
import {
  CONNECTOR_TYPES, buildConfig, connectorTypeInfo, generateToken, initialValues, invalidNumbers, missingRequired,
  type ConfigField, type FieldValues,
} from './connectorTypes'

interface ConnectorFormDialogProps {
  /** The source to edit; leave out to add a new one. */
  connector?: Connector
  onClose: () => void
}

/**
 * Add or edit a data source. Mount it only while it is open so each opening starts clean.
 * The backend never returns stored config, so when editing every field starts empty and
 * only the fields the user fills in are sent.
 */
export function ConnectorFormDialog({ connector, onClose }: ConnectorFormDialogProps) {
  const queryClient = useQueryClient()
  const addNotification = useUIStore((s) => s.addNotification)
  const editing = connector !== undefined

  const [type, setType] = useState<ConnectorType>(connector?.connector_type ?? 'wazuh')
  const info = connectorTypeInfo(type) ?? CONNECTOR_TYPES[0]
  const [name, setName] = useState(connector?.name ?? '')
  const [enabled, setEnabled] = useState(connector?.enabled ?? true)
  const [values, setValues] = useState<FieldValues>(() => initialValues(info.fields))
  const [touched, setTouched] = useState<Set<string>>(new Set())
  const [formError, setFormError] = useState('')

  const selectType = (next: ConnectorType) => {
    setType(next)
    setValues(initialValues(connectorTypeInfo(next)?.fields ?? []))
    setTouched(new Set())
    setFormError('')
  }

  const setField = (key: string, value: string | boolean) => {
    setValues((prev) => ({ ...prev, [key]: value }))
    setTouched((prev) => new Set(prev).add(key))
    setFormError('')
  }

  const saveMutation = useMutation({
    mutationFn: () => {
      if (connector) {
        const config = buildConfig(info.fields, values, touched)
        return connectorsApi.update(connector.id, {
          enabled,
          ...(Object.keys(config).length > 0 ? { config } : {}),
        })
      }
      return connectorsApi.create({
        name: name.trim(),
        connector_type: type,
        config: buildConfig(info.fields, values),
        enabled,
      })
    },
    onSuccess: (saved) => {
      queryClient.invalidateQueries({ queryKey: ['connectors'] })
      addNotification({
        type: 'success',
        title: editing ? 'Source updated' : 'Source added',
        message: editing && saved.status !== 'inactive'
          ? 'Stop and start the source to apply new settings.'
          : saved.name,
      })
      onClose()
    },
    onError: (err: unknown) => {
      const message = apiErrorMessage(err, editing ? 'Could not update the source' : 'Could not add the source')
      setFormError(message)
      addNotification({ type: 'error', title: editing ? 'Update failed' : 'Add failed', message })
    },
  })

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    if (!editing) {
      if (!name.trim()) {
        setFormError('Name is required')
        return
      }
      const missing = missingRequired(info.fields, values)
      if (missing.length > 0) {
        setFormError(`Required: ${missing.join(', ')}`)
        return
      }
    }
    const badNumbers = invalidNumbers(info.fields, values)
    if (badNumbers.length > 0) {
      setFormError(`Enter a whole number above zero: ${badNumbers.join(', ')}`)
      return
    }
    saveMutation.mutate()
  }

  return (
    <Dialog open onOpenChange={(next) => { if (!next) onClose() }}>
      <DialogContent className="max-h-[90vh] max-w-lg overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{editing ? `Edit ${connector.name}` : 'Add data source'}</DialogTitle>
          <DialogDescription>
            {editing
              ? 'Stored settings are not shown. Fill in only the fields you want to change.'
              : 'Choose a source type and enter its connection settings.'}
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit} className="space-y-4" noValidate>
          {!editing && (
            <div className="space-y-1.5">
              <Label className="text-[12px] font-medium">Type</Label>
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
                {CONNECTOR_TYPES.map((t) => (
                  <Button
                    key={t.type}
                    type="button"
                    variant="outline"
                    aria-pressed={type === t.type}
                    onClick={() => selectType(t.type)}
                    className={cn('h-8 justify-start gap-2', type === t.type && 'border-primary bg-primary/10 text-primary')}
                  >
                    <t.icon className="h-3.5 w-3.5" />
                    {t.label}
                  </Button>
                ))}
              </div>
              <p className="text-[11px] text-muted-foreground">{info.description}</p>
            </div>
          )}

          {!editing && (
            <div className="space-y-1.5">
              <Label htmlFor="connector-name" className="text-[12px] font-medium">Name</Label>
              <Input
                id="connector-name"
                value={name}
                maxLength={255}
                placeholder={type === 'generic' ? 'my-webhook' : `${type}-prod`}
                onChange={(e) => { setName(e.target.value); setFormError('') }}
                autoComplete="off"
              />
              {type === 'generic' && (
                <p className="text-[11px] text-muted-foreground">
                  Senders pass this name in the X-MxTac-Source header.
                </p>
              )}
            </div>
          )}

          {info.fields.map((field) => (
            <ConfigFieldInput
              key={`${type}-${field.key}`}
              field={field}
              value={values[field.key]}
              editing={editing}
              onChange={(v) => setField(field.key, v)}
            />
          ))}

          <div className="flex items-center justify-between rounded-lg border border-border p-3">
            <div>
              <Label htmlFor="connector-enabled" className="text-[12px] font-medium">Enabled</Label>
              <p className="text-[11px] text-muted-foreground">Enabled sources start when the server starts.</p>
            </div>
            <Switch id="connector-enabled" checked={enabled} onCheckedChange={setEnabled} />
          </div>

          {formError && (
            <p role="alert" className="rounded-md border sev-critical px-3 py-2 text-[11px]">{formError}</p>
          )}

          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose} disabled={saveMutation.isPending}>Cancel</Button>
            <Button type="submit" disabled={saveMutation.isPending}>
              {saveMutation.isPending ? 'Saving…' : editing ? 'Save changes' : 'Add source'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

interface ConfigFieldInputProps {
  field: ConfigField
  value: string | boolean | undefined
  editing: boolean
  onChange: (value: string | boolean) => void
}

function ConfigFieldInput({ field, value, editing, onChange }: ConfigFieldInputProps) {
  const id = `connector-field-${field.key}`

  if (field.kind === 'boolean') {
    return (
      <div className="flex items-center justify-between">
        <Label htmlFor={id} className="text-[12px] font-medium">{field.label}</Label>
        <Switch id={id} checked={value === true} onCheckedChange={onChange} />
      </div>
    )
  }

  const text = typeof value === 'string' ? value : ''
  const placeholder = editing && field.kind === 'password' ? 'Leave empty to keep the current value' : field.placeholder

  return (
    <div className="space-y-1.5">
      <Label htmlFor={id} className="text-[12px] font-medium">
        {field.label}
        {field.required && !editing && <span className="ml-0.5 text-destructive">*</span>}
      </Label>
      <div className="flex gap-2">
        <Input
          id={id}
          type={field.kind === 'password' ? 'password' : 'text'}
          inputMode={field.kind === 'number' ? 'numeric' : undefined}
          value={text}
          placeholder={placeholder}
          onChange={(e) => onChange(e.target.value)}
          autoComplete={field.kind === 'password' ? 'new-password' : 'off'}
        />
        {field.key === 'webhook_token' && (
          <Button type="button" variant="outline" className="gap-1.5" onClick={() => onChange(generateToken())}>
            <Wand2 className="h-3.5 w-3.5" />
            Generate
          </Button>
        )}
      </div>
      {field.key === 'webhook_token' && text && (
        <code className="block break-all rounded-md bg-muted px-2 py-1 font-mono text-[11px] text-foreground">{text}</code>
      )}
      {field.help && <p className="text-[11px] text-muted-foreground">{field.help}</p>}
    </div>
  )
}
