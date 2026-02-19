import { create } from 'zustand'
import { persist } from 'zustand/middleware'

interface Notification {
  id: string
  type: 'info' | 'success' | 'warning' | 'error'
  title: string
  message?: string
}

interface UIState {
  sidebarCollapsed: boolean
  notifications: Notification[]
  globalError: string | null

  toggleSidebar: () => void
  addNotification: (n: Omit<Notification, 'id'>) => void
  removeNotification: (id: string) => void
  setGlobalError: (msg: string | null) => void
}

let _notifId = 0

export const useUIStore = create<UIState>()(
  persist(
    (set) => ({
      sidebarCollapsed: false,
      notifications: [],
      globalError: null,

      toggleSidebar: () =>
        set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),

      addNotification: (n) => {
        const id = String(++_notifId)
        set((s) => ({ notifications: [...s.notifications, { ...n, id }] }))
        // Auto-dismiss after 5 s
        setTimeout(() => {
          set((s) => ({ notifications: s.notifications.filter((x) => x.id !== id) }))
        }, 5000)
      },

      removeNotification: (id) =>
        set((s) => ({ notifications: s.notifications.filter((x) => x.id !== id) })),

      setGlobalError: (msg) => set({ globalError: msg }),
    }),
    {
      name: 'mxtac-ui',
      partialize: (s) => ({ sidebarCollapsed: s.sidebarCollapsed }),
    },
  ),
)
