import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { useUIStore } from '../../stores/uiStore'

const root = document.documentElement
const stored = () => JSON.parse(localStorage.getItem('mxtac-ui') || '{}')?.state

describe('uiStore', () => {
  beforeEach(() => {
    localStorage.clear()
    useUIStore.getState().setTheme('light')
    useUIStore.setState({
      sidebarCollapsed: false,
      notifications: [],
      showShortcutsModal: false,
    })
  })

  describe('theme', () => {
    it('setTheme("dark") stores the theme and marks <html> as dark', () => {
      useUIStore.getState().setTheme('dark')
      expect(useUIStore.getState().theme).toBe('dark')
      expect(root).toHaveClass('dark')
      expect(root).toHaveAttribute('data-theme', 'dark')
    })

    it('setTheme("light") removes the dark class from <html>', () => {
      useUIStore.getState().setTheme('dark')
      useUIStore.getState().setTheme('light')
      expect(useUIStore.getState().theme).toBe('light')
      expect(root).not.toHaveClass('dark')
      expect(root).toHaveAttribute('data-theme', 'light')
    })

    it('toggleTheme switches between light and dark', () => {
      useUIStore.getState().toggleTheme()
      expect(useUIStore.getState().theme).toBe('dark')
      expect(root).toHaveClass('dark')

      useUIStore.getState().toggleTheme()
      expect(useUIStore.getState().theme).toBe('light')
      expect(root).not.toHaveClass('dark')
    })
  })

  describe('sidebar', () => {
    it('toggleSidebar collapses and expands', () => {
      useUIStore.getState().toggleSidebar()
      expect(useUIStore.getState().sidebarCollapsed).toBe(true)
      useUIStore.getState().toggleSidebar()
      expect(useUIStore.getState().sidebarCollapsed).toBe(false)
    })
  })

  describe('shortcuts modal', () => {
    it('opens and closes', () => {
      useUIStore.getState().openShortcutsModal()
      expect(useUIStore.getState().showShortcutsModal).toBe(true)
      useUIStore.getState().closeShortcutsModal()
      expect(useUIStore.getState().showShortcutsModal).toBe(false)
    })
  })

  describe('notifications', () => {
    beforeEach(() => { vi.useFakeTimers() })
    afterEach(() => { vi.useRealTimers() })

    const add = (title: string) => useUIStore.getState().addNotification({ type: 'info', title })

    it('addNotification appends the notification with a generated id', () => {
      useUIStore.getState().addNotification({ type: 'error', title: 'Save failed', message: 'Try again' })
      const { notifications } = useUIStore.getState()
      expect(notifications).toHaveLength(1)
      expect(notifications[0]).toMatchObject({ type: 'error', title: 'Save failed', message: 'Try again' })
      expect(notifications[0].id).toBeTruthy()
    })

    it('keeps notifications in order and gives each a unique id', () => {
      add('First')
      add('Second')
      const { notifications } = useUIStore.getState()
      expect(notifications.map((n) => n.title)).toEqual(['First', 'Second'])
      expect(notifications[0].id).not.toBe(notifications[1].id)
    })

    it('removeNotification removes only the matching notification', () => {
      add('First')
      add('Second')
      useUIStore.getState().removeNotification(useUIStore.getState().notifications[0].id)
      expect(useUIStore.getState().notifications.map((n) => n.title)).toEqual(['Second'])
    })

    it('removeNotification with an unknown id changes nothing', () => {
      add('First')
      useUIStore.getState().removeNotification('no-such-id')
      expect(useUIStore.getState().notifications).toHaveLength(1)
    })

    it('dismisses a notification after 5 seconds, and not before', () => {
      add('First')
      vi.advanceTimersByTime(4999)
      expect(useUIStore.getState().notifications).toHaveLength(1)
      vi.advanceTimersByTime(1)
      expect(useUIStore.getState().notifications).toHaveLength(0)
    })

    it('auto-dismiss removes only its own notification', () => {
      add('First')
      vi.advanceTimersByTime(3000)
      add('Second')
      vi.advanceTimersByTime(2000)
      expect(useUIStore.getState().notifications.map((n) => n.title)).toEqual(['Second'])
    })
  })

  describe('persistence', () => {
    it('saves the theme and the sidebar state under "mxtac-ui"', () => {
      useUIStore.getState().setTheme('dark')
      useUIStore.getState().toggleSidebar()
      expect(stored()).toEqual({ theme: 'dark', sidebarCollapsed: true })
    })

    it('does not save transient state', () => {
      useUIStore.getState().addNotification({ type: 'error', title: 'err' })
      useUIStore.getState().openShortcutsModal()
      expect(Object.keys(stored()).sort()).toEqual(['sidebarCollapsed', 'theme'])
    })

    it.each(['light', 'dark'] as const)('restores a saved %s theme and applies it to <html>', async (theme) => {
      useUIStore.getState().setTheme(theme === 'light' ? 'dark' : 'light')
      localStorage.setItem('mxtac-ui', JSON.stringify({ state: { theme, sidebarCollapsed: true }, version: 0 }))

      await useUIStore.persist.rehydrate()

      expect(useUIStore.getState().theme).toBe(theme)
      expect(useUIStore.getState().sidebarCollapsed).toBe(true)
      expect(root.classList.contains('dark')).toBe(theme === 'dark')
      expect(root).toHaveAttribute('data-theme', theme)
    })

    it('shows a saved theme that no longer exists (the removed "matrix") as dark', async () => {
      localStorage.setItem('mxtac-ui', JSON.stringify({ state: { theme: 'matrix', sidebarCollapsed: false }, version: 0 }))

      await useUIStore.persist.rehydrate()

      expect(root).toHaveClass('dark')
      expect(root).toHaveAttribute('data-theme', 'dark')
    })
  })
})
