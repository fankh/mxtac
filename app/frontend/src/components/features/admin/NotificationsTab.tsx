import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { notificationChannelsApi } from '../../../lib/api'
import { useUIStore } from '../../../stores/uiStore'
import type { NotificationChannel, NotificationChannelType } from '../../../types/api'
import { ChannelModal } from './ChannelModal'

// ── Icons ─────────────────────────────────────────────────────────────────────

function EmailIcon() {
  return (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round"
        d="M21.75 6.75v10.5a2.25 2.25 0 01-2.25 2.25h-15a2.25 2.25 0 01-2.25-2.25V6.75m19.5 0A2.25 2.25 0 0019.5 4.5h-15a2.25 2.25 0 00-2.25 2.25m19.5 0v.243a2.25 2.25 0 01-1.07 1.916l-7.5 4.615a2.25 2.25 0 01-2.36 0L3.32 8.91a2.25 2.25 0 01-1.07-1.916V6.75" />
    </svg>
  )
}

function WebhookIcon() {
  return (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round"
        d="M13.19 8.688a4.5 4.5 0 011.242 7.244l-4.5 4.5a4.5 4.5 0 01-6.364-6.364l1.757-1.757m13.35-.622l1.757-1.757a4.5 4.5 0 00-6.364-6.364l-4.5 4.5a4.5 4.5 0 001.242 7.244" />
    </svg>
  )
}

function TeamsIcon() {
  return (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round"
        d="M20.25 8.511c.884.284 1.5 1.128 1.5 2.097v4.286c0 1.136-.847 2.1-1.98 2.193-.34.027-.68.052-1.02.072v3.091l-3-3c-1.354 0-2.694-.055-4.02-.163a2.115 2.115 0 01-.825-.242m9.345-8.334a2.126 2.126 0 00-.476-.095 48.64 48.64 0 00-8.048 0c-1.131.094-1.976 1.057-1.976 2.192v4.286c0 .837.46 1.58 1.155 1.951m9.345-8.334V6.637c0-1.621-1.152-3.026-2.76-3.235A48.455 48.455 0 0011.25 3c-2.115 0-4.198.137-6.24.402-1.608.209-2.76 1.614-2.76 3.235v6.226c0 1.621 1.152 3.026 2.76 3.235.577.075 1.157.14 1.74.194V21l4.155-4.155" />
    </svg>
  )
}

function ChannelTypeIcon({ type }: { type: NotificationChannelType }) {
  const base = 'w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0'
  switch (type) {
    case 'email':
      return <div className={`${base} bg-blue/10 text-blue`}><EmailIcon /></div>
    case 'slack':
      return (
        <div className={`${base} bg-purple-500/10 text-purple-400 font-bold text-[15px]`}>
          #
        </div>
      )
    case 'webhook':
      return <div className={`${base} bg-status-ok/10 text-status-ok`}><WebhookIcon /></div>
    case 'msteams':
      return <div className={`${base} bg-high-bg text-high-text`}><TeamsIcon /></div>
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const CHANNEL_LABELS: Record<NotificationChannelType, string> = {
  email:   'Email',
  slack:   'Slack',
  webhook: 'Webhook',
  msteams: 'Microsoft Teams',
}

const SEV_COLORS: Record<string, string> = {
  critical: 'text-crit-text bg-crit-bg',
  high:     'text-high-text bg-high-bg',
  medium:   'text-yellow-400 bg-yellow-400/10',
  low:      'text-text-muted bg-page border border-border',
}

// ── NotificationsTab ──────────────────────────────────────────────────────────

export function NotificationsTab() {
  const queryClient = useQueryClient()
  const { addNotification } = useUIStore()
  const [showModal, setShowModal]       = useState(false)
  const [editingChannel, setEditingChannel] = useState<NotificationChannel | undefined>()

  // Track last test result per channel (session-only, not persisted)
  const [testResults, setTestResults] = useState<Record<number, { sent: boolean }>>({})

  const { data, isLoading } = useQuery({
    queryKey: ['notification-channels'],
    queryFn:  () => notificationChannelsApi.list({ page_size: 100 }),
  })
  const channels = data?.items ?? []

  const toggleEnabled = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) =>
      notificationChannelsApi.update(id, { enabled }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['notification-channels'] }),
    onError:   () => addNotification({ type: 'error', title: 'Update failed', message: 'Could not toggle channel.' }),
  })

  const deleteChannel = useMutation({
    mutationFn: (id: number) => notificationChannelsApi.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notification-channels'] })
      addNotification({ type: 'success', title: 'Channel deleted' })
    },
    onError: () => addNotification({ type: 'error', title: 'Delete failed', message: 'Could not delete channel.' }),
  })

  const testChannel = useMutation({
    mutationFn: (id: number) => notificationChannelsApi.test(id),
    onSuccess: (result) => {
      setTestResults(prev => ({ ...prev, [result.channel_id]: { sent: result.sent } }))
      addNotification({
        type:    result.sent ? 'success' : 'error',
        title:   result.sent ? 'Test notification sent' : 'Test notification failed',
        message: result.message,
      })
    },
    onError: () =>
      addNotification({ type: 'error', title: 'Test failed', message: 'Could not reach notification service.' }),
  })

  function handleDelete(ch: NotificationChannel) {
    if (confirm(`Delete channel "${ch.name}"? This cannot be undone.`)) {
      deleteChannel.mutate(ch.id)
    }
  }

  function openCreate() {
    setEditingChannel(undefined)
    setShowModal(true)
  }

  function openEdit(ch: NotificationChannel) {
    setEditingChannel(ch)
    setShowModal(true)
  }

  function closeModal() {
    setShowModal(false)
    setEditingChannel(undefined)
  }

  return (
    <div>
      {/* Header */}
      <div className="flex items-start justify-between mb-4">
        <div>
          <h2 className="text-[13px] font-semibold text-text-primary">Notification Channels</h2>
          <p className="text-[10px] text-text-muted mt-0.5">
            Configure where alerts are delivered when detection rules fire.
          </p>
        </div>
        <button
          onClick={openCreate}
          className="h-[28px] px-4 bg-blue text-white text-[12px] rounded-md hover:opacity-90 flex-shrink-0"
        >
          + Add Channel
        </button>
      </div>

      {/* Channel grid */}
      {isLoading ? (
        <div className="flex items-center justify-center h-24 text-text-muted text-[12px]">
          Loading…
        </div>
      ) : channels.length === 0 ? (
        <div className="flex flex-col items-center justify-center h-40 gap-2">
          <span className="text-[12px] text-text-muted">No notification channels configured.</span>
          <button onClick={openCreate} className="text-[12px] text-blue hover:underline">
            Add your first channel
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-3 gap-3">
          {channels.map(ch => {
            const isTestingThis = testChannel.isPending && testChannel.variables === ch.id
            const lastTest      = testResults[ch.id]

            return (
              <div key={ch.id} className="bg-surface border border-border rounded-lg p-4 flex flex-col">

                {/* Card header: icon + name + on/off */}
                <div className="flex items-start gap-3 mb-3">
                  <ChannelTypeIcon type={ch.channel_type} />
                  <div className="flex-1 min-w-0">
                    <div className="text-[12px] font-semibold text-text-primary truncate">{ch.name}</div>
                    <div className="text-[10px] text-text-muted">{CHANNEL_LABELS[ch.channel_type]}</div>
                  </div>
                  {/* Enabled toggle */}
                  <button
                    onClick={() => toggleEnabled.mutate({ id: ch.id, enabled: !ch.enabled })}
                    disabled={toggleEnabled.isPending}
                    className={`flex-shrink-0 text-[10px] font-medium px-2 py-[2px] rounded transition-colors ${
                      ch.enabled
                        ? 'bg-status-ok/10 text-status-ok'
                        : 'bg-page text-text-muted border border-border'
                    }`}
                  >
                    {ch.enabled ? 'On' : 'Off'}
                  </button>
                </div>

                {/* Min severity */}
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-[9px] text-text-muted uppercase font-medium">Min:</span>
                  <span className={`text-[9px] font-medium px-1.5 py-[1px] rounded capitalize ${SEV_COLORS[ch.min_severity] ?? ''}`}>
                    {ch.min_severity}
                  </span>
                </div>

                {/* Last test status (session-only) */}
                {lastTest && (
                  <div className={`text-[9px] mb-2 ${lastTest.sent ? 'text-status-ok' : 'text-crit-text'}`}>
                    Last test: {lastTest.sent ? 'Passed' : 'Failed'}
                  </div>
                )}

                {/* Spacer */}
                <div className="flex-1" />

                {/* Actions */}
                <div className="flex items-center gap-2 pt-3 border-t border-section mt-2">
                  <button
                    onClick={() => testChannel.mutate(ch.id)}
                    disabled={isTestingThis}
                    className="text-[10px] font-medium text-blue hover:opacity-70 disabled:opacity-40"
                  >
                    {isTestingThis ? 'Testing…' : 'Test'}
                  </button>
                  <button
                    onClick={() => openEdit(ch)}
                    className="text-[10px] text-text-muted hover:text-text-primary"
                  >
                    Edit
                  </button>
                  <button
                    onClick={() => handleDelete(ch)}
                    disabled={deleteChannel.isPending}
                    className="text-[10px] text-crit-text hover:opacity-70 disabled:opacity-40 ml-auto"
                  >
                    Delete
                  </button>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* Create / edit modal */}
      {showModal && (
        <ChannelModal
          channel={editingChannel}
          onClose={closeModal}
          onSaved={() => {}}
        />
      )}
    </div>
  )
}
