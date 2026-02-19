import { useUIStore } from '../../stores/uiStore'

const TYPE_STYLES = {
  info:    'border-blue bg-[#EBF3FF] text-blue',
  success: 'border-[#28A745] bg-[#EAF7ED] text-[#1A7A30]',
  warning: 'border-[#F0A020] bg-[#FEF8EC] text-[#9A6600]',
  error:   'border-crit-text bg-[#FDECEA] text-crit-text',
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
            ×
          </button>
        </div>
      ))}
    </div>
  )
}
