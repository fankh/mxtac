import { create } from 'zustand'
import { persist } from 'zustand/middleware'

export type Theme = 'light' | 'dark'

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
  showShortcutsModal: boolean

  setTheme: (t: Theme) => void
  toggleTheme: () => void
  toggleSidebar: () => void
  addNotification: (n: Omit<Notification, 'id'>) => void
  removeNotification: (id: string) => void
  openShortcutsModal: () => void
  closeShortcutsModal: () => void
}

let _notifId = 0

function applyTheme(theme: Theme) {
  document.documentElement.setAttribute('data-theme', theme)
  document.documentElement.classList.toggle('dark', theme !== 'light')
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

      openShortcutsModal: () => set({ showShortcutsModal: true }),
      closeShortcutsModal: () => set({ showShortcutsModal: false }),
    }),
    {
      name: 'mxtac-ui',
      partialize: (s) => ({ sidebarCollapsed: s.sidebarCollapsed, theme: s.theme }),
      // A theme stored by an older version (for example 'matrix') falls back to dark
      merge: (persisted, current) => {
        const saved = (persisted ?? {}) as Partial<UIState>
        return { ...current, ...saved, theme: saved.theme === 'light' ? 'light' : saved.theme ? 'dark' : current.theme }
      },
      onRehydrateStorage: () => (state) => {
        if (state?.theme) applyTheme(state.theme)
      },
    },
  ),
)
