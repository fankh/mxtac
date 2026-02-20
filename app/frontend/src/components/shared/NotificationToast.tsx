import { useUIStore } from '../../stores/uiStore'

const TYPE_STYLES = {
  info:    'border-blue bg-blue-light text-blue',
  success: 'border-status-ok bg-status-ok-bg text-status-ok-text',
  warning: 'border-status-warn bg-status-warn-bg text-status-warn-text',
  error:   'border-crit-text bg-crit-bg text-crit-text',
}

export function NotificationToast() {
  const { notifications, removeNotification } = useUIStore()

  if (notifications.length === 0) return null

  return (
    <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 w-[320px]">
      {notifications.map((n) => (
        <div
          key={n.id}
          className={`rounded-md border px-4 py-3 shadow-panel flex items-start gap-2 ${TYPE_STYLES[n.type]}`}
        >
          <div className="flex-1 min-w-0">
            <div className="text-[12px] font-semibold">{n.title}</div>
            {n.message && <div className="text-[11px] mt-[2px] opacity-80">{n.message}</div>}
          </div>
          <button
            className="text-[14px] opacity-60 hover:opacity-100 leading-none"
            onClick={() => removeNotification(n.id)}
          >
            {'\u00D7'}
          </button>
        </div>
      ))}
    </div>
  )
}
