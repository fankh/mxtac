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
  showShortcutsModal: boolean

  setTheme: (t: Theme) => void
  toggleTheme: () => void
  toggleSidebar: () => void
  addNotification: (n: Omit<Notification, 'id'>) => void
  removeNotification: (id: string) => void
  setGlobalError: (msg: string | null) => void
  openShortcutsModal: () => void
  closeShortcutsModal: () => void
}

let _notifId = 0

function applyTheme(theme: Theme) {
  document.documentElement.setAttribute('data-theme', theme)
}

function getSystemTheme(): 'light' | 'dark' {
  if (typeof window !== 'undefined' && window.matchMedia?.('(prefers-color-scheme: light)').matches) {
    return 'light'
  }
  return 'dark'
}

export const useUIStore = create<UIState>()(
  persist(
    (set, get) => ({
      theme: getSystemTheme(),
      sidebarCollapsed: false,
      notifications: [],
      globalError: null,
      showShortcutsModal: false,

      setTheme: (theme) => {
        applyTheme(theme)
        set({ theme })
      },

      toggleTheme: () => {
        const current = get().theme
        const next: Theme = current === 'dark' ? 'light' : 'dark'
        applyTheme(next)
        set({ theme: next })
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

      openShortcutsModal: () => set({ showShortcutsModal: true }),
      closeShortcutsModal: () => set({ showShortcutsModal: false }),
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
