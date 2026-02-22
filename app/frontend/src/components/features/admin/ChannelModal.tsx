import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { notificationChannelsApi } from '../../../lib/api'
import { useUIStore } from '../../../stores/uiStore'
import type { NotificationChannel, NotificationChannelType, SeverityLevel } from '../../../types/api'

const CHANNEL_TYPES: { value: NotificationChannelType; label: string }[] = [
  { value: 'email',    label: 'Email' },
  { value: 'slack',    label: 'Slack' },
  { value: 'webhook',  label: 'Webhook' },
  { value: 'msteams',  label: 'Teams' },
]

const SEVERITIES: SeverityLevel[] = ['critical', 'high', 'medium', 'low']

interface Props {
  channel?: NotificationChannel   // undefined = create mode
  onClose: () => void
  onSaved: () => void
}

export function ChannelModal({ channel, onClose, onSaved }: Props) {
  const queryClient = useQueryClient()
  const { addNotification } = useUIStore()
  const isEdit = !!channel

  // Shared fields
  const [name, setName] = useState(channel?.name ?? '')
  const [channelType, setChannelType] = useState<NotificationChannelType>(channel?.channel_type ?? 'email')
  const [minSeverity, setMinSeverity] = useState<SeverityLevel>(channel?.min_severity ?? 'low')

  // Email config state
  const [emailConfig, setEmailConfig] = useState({
    smtp_host:     String(channel?.config?.smtp_host ?? ''),
    smtp_port:     Number(channel?.config?.smtp_port ?? 587),
    from_address:  String(channel?.config?.from_address ?? ''),
    to_addresses:  Array.isArray(channel?.config?.to_addresses)
                     ? (channel!.config.to_addresses as string[])
                     : [],
    use_tls:       channel?.config?.use_tls !== undefined ? Boolean(channel.config.use_tls) : true,
    username:      String(channel?.config?.username ?? ''),
    password:      '',   // never pre-fill password
  })
  const [toInput, setToInput] = useState('')

  // Slack config state
  const [slackConfig, setSlackConfig] = useState({
    webhook_url: String(channel?.config?.webhook_url ?? ''),
    channel:     String(channel?.config?.channel ?? ''),
    username:    String(channel?.config?.username ?? ''),
  })

  // Webhook config state
  const [webhookConfig, setWebhookConfig] = useState({
    url:        String(channel?.config?.url ?? ''),
    method:     String(channel?.config?.method ?? 'POST'),
    headers:    (channel?.config?.headers &&
                 typeof channel.config.headers === 'object' &&
                 !Array.isArray(channel.config.headers))
                  ? (channel.config.headers as Record<string, string>)
                  : {} as Record<string, string>,
    auth_token: String(channel?.config?.auth_token ?? ''),
  })
  const [headerKey, setHeaderKey] = useState('')
  const [headerVal, setHeaderVal] = useState('')

  // Teams config state
  const [teamsConfig, setTeamsConfig] = useState({
    webhook_url: String(channel?.config?.webhook_url ?? ''),
  })

  const activeType = isEdit ? channel!.channel_type : channelType

  function buildConfig(): Record<string, unknown> {
    switch (activeType) {
      case 'email':
        return {
          smtp_host:    emailConfig.smtp_host,
          smtp_port:    emailConfig.smtp_port,
          from_address: emailConfig.from_address,
          to_addresses: emailConfig.to_addresses,
          use_tls:      emailConfig.use_tls,
          ...(emailConfig.username ? { username: emailConfig.username } : {}),
          ...(emailConfig.password ? { password: emailConfig.password } : {}),
        }
      case 'slack':
        return {
          webhook_url: slackConfig.webhook_url,
          ...(slackConfig.channel  ? { channel:  slackConfig.channel }  : {}),
          ...(slackConfig.username ? { username: slackConfig.username } : {}),
        }
      case 'webhook':
        return {
          url:    webhookConfig.url,
          method: webhookConfig.method,
          ...(Object.keys(webhookConfig.headers).length ? { headers: webhookConfig.headers } : {}),
          ...(webhookConfig.auth_token ? { auth_token: webhookConfig.auth_token } : {}),
        }
      case 'msteams':
        return { webhook_url: teamsConfig.webhook_url }
    }
  }

  const saveMutation = useMutation({
    mutationFn: () => {
      if (isEdit) {
        return notificationChannelsApi.update(channel!.id, {
          config: buildConfig(),
          min_severity: minSeverity,
        })
      }
      return notificationChannelsApi.create({
        name,
        channel_type: channelType,
        config: buildConfig(),
        min_severity: minSeverity,
      })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notification-channels'] })
      addNotification({
        type: 'success',
        title: isEdit ? 'Channel updated' : 'Channel created',
        message: isEdit ? `${channel!.name} has been updated.` : `${name} has been created.`,
      })
      onSaved()
      onClose()
    },
    onError: (err: unknown) => {
      const detail = (err as { response?: { data?: { detail?: string } } })
        ?.response?.data?.detail ?? 'Failed to save channel.'
      addNotification({ type: 'error', title: 'Save failed', message: detail })
    },
  })

  function addToAddress() {
    const addr = toInput.trim()
    if (addr && !emailConfig.to_addresses.includes(addr)) {
      setEmailConfig(c => ({ ...c, to_addresses: [...c.to_addresses, addr] }))
      setToInput('')
    }
  }

  function removeToAddress(addr: string) {
    setEmailConfig(c => ({ ...c, to_addresses: c.to_addresses.filter(a => a !== addr) }))
  }

  function addHeader() {
    if (headerKey.trim() && headerVal.trim()) {
      setWebhookConfig(c => ({ ...c, headers: { ...c.headers, [headerKey.trim()]: headerVal.trim() } }))
      setHeaderKey('')
      setHeaderVal('')
    }
  }

  function removeHeader(key: string) {
    setWebhookConfig(c => {
      const h = { ...c.headers }
      delete h[key]
      return { ...c, headers: h }
    })
  }

  const inputCls = 'w-full h-[32px] px-3 text-[11px] bg-page border border-border rounded-md text-text-primary placeholder-text-muted focus:outline-none focus:border-blue'
  const labelCls = 'text-[10px] font-medium text-text-muted uppercase mb-1 block'

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
      <div className="bg-surface border border-border rounded-lg shadow-panel w-[500px] max-h-[90vh] flex flex-col">

        {/* Header */}
        <div className="flex items-center justify-between px-5 py-3 border-b border-border flex-shrink-0">
          <h2 className="text-[13px] font-semibold text-text-primary">
            {isEdit ? `Edit: ${channel!.name}` : 'New Notification Channel'}
          </h2>
          <button onClick={onClose} className="text-text-muted hover:text-text-primary text-[18px] leading-none">×</button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-5 py-4 space-y-4">

          {/* Create mode: name + type */}
          {!isEdit && (
            <>
              <div>
                <label className={labelCls}>Channel Name</label>
                <input
                  value={name}
                  onChange={e => setName(e.target.value)}
                  placeholder="e.g. SOC Slack Alerts"
                  className={inputCls}
                />
              </div>

              <div>
                <label className={labelCls}>Channel Type</label>
                <div className="grid grid-cols-4 gap-2">
                  {CHANNEL_TYPES.map(({ value, label }) => (
                    <button
                      key={value}
                      type="button"
                      onClick={() => setChannelType(value)}
                      className={`py-2 rounded-md text-[11px] font-medium border transition-colors ${
                        channelType === value
                          ? 'border-blue bg-blue/10 text-blue'
                          : 'border-border bg-page text-text-muted hover:border-blue/50'
                      }`}
                    >
                      {label}
                    </button>
                  ))}
                </div>
              </div>
            </>
          )}

          {/* Edit mode: name + type as read-only */}
          {isEdit && (
            <div className="flex items-center gap-4 text-[11px]">
              <span className="text-text-muted">Type:</span>
              <span className="text-text-primary font-medium capitalize">
                {CHANNEL_TYPES.find(t => t.value === activeType)?.label ?? activeType}
              </span>
            </div>
          )}

          {/* Min severity */}
          <div>
            <label className={labelCls}>Min Severity</label>
            <div className="flex gap-2">
              {SEVERITIES.map(sev => (
                <button
                  key={sev}
                  type="button"
                  onClick={() => setMinSeverity(sev)}
                  className={`px-3 py-1 rounded text-[10px] font-medium capitalize transition-colors ${
                    minSeverity === sev
                      ? 'bg-blue text-white'
                      : 'bg-page border border-border text-text-muted hover:border-blue/50'
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>
          </div>

          {/* ── Email config ─────────────────────────────────────────────────── */}
          {activeType === 'email' && (
            <div className="space-y-3">
              <div className="text-[10px] font-semibold text-text-muted uppercase border-b border-section pb-1">
                SMTP Configuration
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className={labelCls}>SMTP Host</label>
                  <input
                    value={emailConfig.smtp_host}
                    onChange={e => setEmailConfig(c => ({ ...c, smtp_host: e.target.value }))}
                    placeholder="smtp.example.com"
                    className={inputCls}
                  />
                </div>
                <div>
                  <label className={labelCls}>Port</label>
                  <input
                    type="number"
                    value={emailConfig.smtp_port}
                    onChange={e => setEmailConfig(c => ({ ...c, smtp_port: Number(e.target.value) }))}
                    className={inputCls}
                  />
                </div>
              </div>

              <div>
                <label className={labelCls}>From Address</label>
                <input
                  value={emailConfig.from_address}
                  onChange={e => setEmailConfig(c => ({ ...c, from_address: e.target.value }))}
                  placeholder="alerts@example.com"
                  className={inputCls}
                />
              </div>

              <div>
                <label className={labelCls}>To Addresses</label>
                <div className="flex gap-2 mb-2">
                  <input
                    value={toInput}
                    onChange={e => setToInput(e.target.value)}
                    onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); addToAddress() } }}
                    placeholder="user@example.com"
                    className="flex-1 h-[32px] px-3 text-[11px] bg-page border border-border rounded-md text-text-primary placeholder-text-muted focus:outline-none focus:border-blue"
                  />
                  <button
                    type="button"
                    onClick={addToAddress}
                    className="h-[32px] px-3 text-[11px] bg-blue text-white rounded-md hover:opacity-90 flex-shrink-0"
                  >
                    Add
                  </button>
                </div>
                {emailConfig.to_addresses.length > 0 && (
                  <div className="flex flex-wrap gap-1">
                    {emailConfig.to_addresses.map(addr => (
                      <span
                        key={addr}
                        className="flex items-center gap-1 px-2 py-[2px] bg-page border border-border rounded text-[10px] text-text-primary"
                      >
                        {addr}
                        <button
                          type="button"
                          onClick={() => removeToAddress(addr)}
                          className="text-text-muted hover:text-crit-text leading-none ml-0.5"
                        >
                          ×
                        </button>
                      </span>
                    ))}
                  </div>
                )}
              </div>

              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  id="use_tls"
                  checked={emailConfig.use_tls}
                  onChange={e => setEmailConfig(c => ({ ...c, use_tls: e.target.checked }))}
                  className="cursor-pointer"
                />
                <label htmlFor="use_tls" className="text-[11px] text-text-secondary cursor-pointer">
                  Use TLS
                </label>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className={labelCls}>Username (optional)</label>
                  <input
                    value={emailConfig.username}
                    onChange={e => setEmailConfig(c => ({ ...c, username: e.target.value }))}
                    placeholder="smtp_user"
                    className={inputCls}
                  />
                </div>
                <div>
                  <label className={labelCls}>Password (optional)</label>
                  <input
                    type="password"
                    value={emailConfig.password}
                    onChange={e => setEmailConfig(c => ({ ...c, password: e.target.value }))}
                    placeholder={isEdit ? '••••••••' : ''}
                    className={inputCls}
                  />
                </div>
              </div>
            </div>
          )}

          {/* ── Slack config ─────────────────────────────────────────────────── */}
          {activeType === 'slack' && (
            <div className="space-y-3">
              <div className="text-[10px] font-semibold text-text-muted uppercase border-b border-section pb-1">
                Slack Configuration
              </div>

              <div>
                <label className={labelCls}>Incoming Webhook URL *</label>
                <input
                  value={slackConfig.webhook_url}
                  onChange={e => setSlackConfig(c => ({ ...c, webhook_url: e.target.value }))}
                  placeholder="https://hooks.slack.com/services/..."
                  className={inputCls}
                />
              </div>

              <div>
                <label className={labelCls}>Channel Override (optional)</label>
                <input
                  value={slackConfig.channel}
                  onChange={e => setSlackConfig(c => ({ ...c, channel: e.target.value }))}
                  placeholder="#alerts"
                  className={inputCls}
                />
              </div>

              <div>
                <label className={labelCls}>Username Override (optional)</label>
                <input
                  value={slackConfig.username}
                  onChange={e => setSlackConfig(c => ({ ...c, username: e.target.value }))}
                  placeholder="MxTac Alerts"
                  className={inputCls}
                />
              </div>
            </div>
          )}

          {/* ── Webhook config ───────────────────────────────────────────────── */}
          {activeType === 'webhook' && (
            <div className="space-y-3">
              <div className="text-[10px] font-semibold text-text-muted uppercase border-b border-section pb-1">
                Webhook Configuration
              </div>

              <div>
                <label className={labelCls}>URL *</label>
                <input
                  value={webhookConfig.url}
                  onChange={e => setWebhookConfig(c => ({ ...c, url: e.target.value }))}
                  placeholder="https://webhook.example.com/alerts"
                  className={inputCls}
                />
              </div>

              <div>
                <label className={labelCls}>HTTP Method</label>
                <select
                  value={webhookConfig.method}
                  onChange={e => setWebhookConfig(c => ({ ...c, method: e.target.value }))}
                  className="w-full h-[32px] px-3 text-[11px] bg-page border border-border rounded-md text-text-primary focus:outline-none focus:border-blue"
                >
                  {['POST', 'PUT', 'PATCH'].map(m => (
                    <option key={m} value={m}>{m}</option>
                  ))}
                </select>
              </div>

              <div>
                <label className={labelCls}>Auth Token (optional)</label>
                <input
                  value={webhookConfig.auth_token}
                  onChange={e => setWebhookConfig(c => ({ ...c, auth_token: e.target.value }))}
                  placeholder="Bearer token value"
                  className={inputCls}
                />
              </div>

              <div>
                <label className={labelCls}>Custom Headers</label>
                <div className="flex gap-2 mb-2">
                  <input
                    value={headerKey}
                    onChange={e => setHeaderKey(e.target.value)}
                    placeholder="Header name"
                    className="flex-1 h-[32px] px-3 text-[11px] bg-page border border-border rounded-md text-text-primary placeholder-text-muted focus:outline-none focus:border-blue"
                  />
                  <input
                    value={headerVal}
                    onChange={e => setHeaderVal(e.target.value)}
                    onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); addHeader() } }}
                    placeholder="Value"
                    className="flex-1 h-[32px] px-3 text-[11px] bg-page border border-border rounded-md text-text-primary placeholder-text-muted focus:outline-none focus:border-blue"
                  />
                  <button
                    type="button"
                    onClick={addHeader}
                    className="h-[32px] px-3 text-[11px] bg-blue text-white rounded-md hover:opacity-90 flex-shrink-0"
                  >
                    Add
                  </button>
                </div>
                {Object.entries(webhookConfig.headers).length > 0 && (
                  <div className="space-y-1">
                    {Object.entries(webhookConfig.headers).map(([k, v]) => (
                      <div
                        key={k}
                        className="flex items-center gap-2 px-2 py-1 bg-page border border-border rounded text-[10px]"
                      >
                        <span className="text-text-muted font-mono">{k}:</span>
                        <span className="text-text-primary flex-1 truncate">{v}</span>
                        <button
                          type="button"
                          onClick={() => removeHeader(k)}
                          className="text-text-muted hover:text-crit-text leading-none flex-shrink-0"
                        >
                          ×
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ── Teams config ─────────────────────────────────────────────────── */}
          {activeType === 'msteams' && (
            <div className="space-y-3">
              <div className="text-[10px] font-semibold text-text-muted uppercase border-b border-section pb-1">
                Microsoft Teams Configuration
              </div>

              <div>
                <label className={labelCls}>Incoming Webhook URL *</label>
                <input
                  value={teamsConfig.webhook_url}
                  onChange={e => setTeamsConfig(c => ({ ...c, webhook_url: e.target.value }))}
                  placeholder="https://outlook.office.com/webhook/..."
                  className={inputCls}
                />
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-2 px-5 py-3 border-t border-border flex-shrink-0">
          <button
            onClick={onClose}
            className="h-[30px] px-4 text-[11px] text-text-muted border border-border rounded-md hover:text-text-primary"
          >
            Cancel
          </button>
          <button
            onClick={() => saveMutation.mutate()}
            disabled={saveMutation.isPending}
            className="h-[30px] px-5 text-[11px] bg-blue text-white rounded-md hover:opacity-90 disabled:opacity-50"
          >
            {saveMutation.isPending ? 'Saving…' : (isEdit ? 'Save Changes' : 'Create Channel')}
          </button>
        </div>
      </div>
    </div>
  )
}
