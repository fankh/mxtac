import { create } from 'zustand'
import { persist } from 'zustand/middleware'

export type Theme = 'light' | 'dark' | 'matrix'

interface Notification {
  id: string
  type: 'info' | 'success' | 'warning' | 'error'
  title: string
  message?: string
}

interface UIState {
  theme: Theme
  sidebarCollapsed: boolean
  notifications: Notification[]
  globalError: string | null

  setTheme: (t: Theme) => void
  toggleSidebar: () => void
  addNotification: (n: Omit<Notification, 'id'>) => void
  removeNotification: (id: string) => void
  setGlobalError: (msg: string | null) => void
}

let _notifId = 0

function applyTheme(theme: Theme) {
  document.documentElement.setAttribute('data-theme', theme)
}

export const useUIStore = create<UIState>()(
  persist(
    (set) => ({
      theme: 'light',
      sidebarCollapsed: false,
      notifications: [],
      globalError: null,

      setTheme: (theme) => {
        applyTheme(theme)
        set({ theme })
      },

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
      partialize: (s) => ({ sidebarCollapsed: s.sidebarCollapsed, theme: s.theme }),
      onRehydrateStorage: () => (state) => {
        if (state?.theme) applyTheme(state.theme)
      },
    },
  ),
)
