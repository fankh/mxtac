import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { useUIStore } from '../../stores/uiStore'

describe('uiStore', () => {
  beforeEach(() => {
    useUIStore.setState({
      theme: 'light',
      sidebarCollapsed: false,
      notifications: [],
      globalError: null,
    })
  })

  // ---------------------------------------------------------------------------
  // Initial state
  // ---------------------------------------------------------------------------
  describe('default state', () => {
    it('theme defaults to "light"', () => {
      expect(useUIStore.getState().theme).toBe('light')
    })

    it('sidebarCollapsed defaults to false', () => {
      expect(useUIStore.getState().sidebarCollapsed).toBe(false)
    })

    it('notifications defaults to an empty array', () => {
      expect(useUIStore.getState().notifications).toEqual([])
    })

    it('globalError defaults to null', () => {
      expect(useUIStore.getState().globalError).toBeNull()
    })
  })

  // ---------------------------------------------------------------------------
  // setTheme
  // ---------------------------------------------------------------------------
  describe('setTheme', () => {
    it('updates theme to "dark"', () => {
      useUIStore.getState().setTheme('dark')
      expect(useUIStore.getState().theme).toBe('dark')
    })

    it('updates theme to "matrix"', () => {
      useUIStore.getState().setTheme('matrix')
      expect(useUIStore.getState().theme).toBe('matrix')
    })

    it('updates theme back to "light"', () => {
      useUIStore.getState().setTheme('dark')
      useUIStore.getState().setTheme('light')
      expect(useUIStore.getState().theme).toBe('light')
    })

    it('applies data-theme attribute to document.documentElement', () => {
      useUIStore.getState().setTheme('matrix')
      expect(document.documentElement.getAttribute('data-theme')).toBe('matrix')
    })

    it('overwrites previous data-theme when changed', () => {
      useUIStore.getState().setTheme('dark')
      useUIStore.getState().setTheme('light')
      expect(document.documentElement.getAttribute('data-theme')).toBe('light')
    })
  })

  // ---------------------------------------------------------------------------
  // toggleSidebar
  // ---------------------------------------------------------------------------
  describe('toggleSidebar', () => {
    it('toggles sidebarCollapsed from false to true', () => {
      useUIStore.getState().toggleSidebar()
      expect(useUIStore.getState().sidebarCollapsed).toBe(true)
    })

    it('toggles sidebarCollapsed from true to false', () => {
      useUIStore.setState({ sidebarCollapsed: true })
      useUIStore.getState().toggleSidebar()
      expect(useUIStore.getState().sidebarCollapsed).toBe(false)
    })

    it('two consecutive toggles return to original state', () => {
      useUIStore.getState().toggleSidebar()
      useUIStore.getState().toggleSidebar()
      expect(useUIStore.getState().sidebarCollapsed).toBe(false)
    })
  })

  // ---------------------------------------------------------------------------
  // addNotification / removeNotification
  // ---------------------------------------------------------------------------
  describe('notifications', () => {
    it('addNotification appends a notification with an auto-generated id', () => {
      useUIStore.getState().addNotification({ type: 'info', title: 'Test alert' })
      const { notifications } = useUIStore.getState()
      expect(notifications).toHaveLength(1)
      expect(notifications[0].title).toBe('Test alert')
      expect(notifications[0].type).toBe('info')
      expect(notifications[0].id).toBeDefined()
      expect(typeof notifications[0].id).toBe('string')
    })

    it('addNotification includes optional message field when provided', () => {
      useUIStore.getState().addNotification({
        type: 'success',
        title: 'Saved',
        message: 'Changes saved successfully',
      })
      expect(useUIStore.getState().notifications[0].message).toBe('Changes saved successfully')
    })

    it('addNotification works without a message field', () => {
      useUIStore.getState().addNotification({ type: 'warning', title: 'No message' })
      expect(useUIStore.getState().notifications[0].message).toBeUndefined()
    })

    it('each of the four notification types can be added', () => {
      const types = ['info', 'success', 'warning', 'error'] as const
      types.forEach((type) =>
        useUIStore.getState().addNotification({ type, title: `${type} alert` }),
      )
      const { notifications } = useUIStore.getState()
      expect(notifications).toHaveLength(4)
      types.forEach((type, i) => {
        expect(notifications[i].type).toBe(type)
      })
    })

    it('multiple notifications accumulate in order', () => {
      useUIStore.getState().addNotification({ type: 'info', title: 'First' })
      useUIStore.getState().addNotification({ type: 'error', title: 'Second' })
      const { notifications } = useUIStore.getState()
      expect(notifications).toHaveLength(2)
      expect(notifications[0].title).toBe('First')
      expect(notifications[1].title).toBe('Second')
    })

    it('each notification receives a unique id', () => {
      useUIStore.getState().addNotification({ type: 'info', title: 'A' })
      useUIStore.getState().addNotification({ type: 'info', title: 'B' })
      const { notifications } = useUIStore.getState()
      expect(notifications[0].id).not.toBe(notifications[1].id)
    })

    it('removeNotification removes the matching notification', () => {
      useUIStore.getState().addNotification({ type: 'info', title: 'Remove me' })
      const id = useUIStore.getState().notifications[0].id
      useUIStore.getState().removeNotification(id)
      expect(useUIStore.getState().notifications).toHaveLength(0)
    })

    it('removeNotification leaves other notifications untouched', () => {
      useUIStore.getState().addNotification({ type: 'info', title: 'Keep me' })
      useUIStore.getState().addNotification({ type: 'error', title: 'Remove me' })
      const idToRemove = useUIStore.getState().notifications[1].id
      useUIStore.getState().removeNotification(idToRemove)

      const { notifications } = useUIStore.getState()
      expect(notifications).toHaveLength(1)
      expect(notifications[0].title).toBe('Keep me')
    })

    it('removeNotification with an unknown id is a no-op', () => {
      useUIStore.getState().addNotification({ type: 'info', title: 'Stay' })
      useUIStore.getState().removeNotification('nonexistent-id')
      expect(useUIStore.getState().notifications).toHaveLength(1)
    })

    describe('auto-dismiss', () => {
      beforeEach(() => { vi.useFakeTimers() })
      afterEach(() => { vi.useRealTimers() })

      it('notification is auto-dismissed after 5 000 ms', () => {
        useUIStore.getState().addNotification({ type: 'info', title: 'Temp' })
        expect(useUIStore.getState().notifications).toHaveLength(1)

        vi.advanceTimersByTime(5000)
        expect(useUIStore.getState().notifications).toHaveLength(0)
      })

      it('notification is still present before 5 000 ms elapses', () => {
        useUIStore.getState().addNotification({ type: 'info', title: 'Still here' })
        vi.advanceTimersByTime(4999)
        expect(useUIStore.getState().notifications).toHaveLength(1)
      })

      it('auto-dismiss only removes its own notification, not others', () => {
        useUIStore.getState().addNotification({ type: 'info', title: 'First' })
        // Add a second notification 2.5 s later
        vi.advanceTimersByTime(2500)
        useUIStore.getState().addNotification({ type: 'error', title: 'Second' })

        // First notification's 5 s timer fires here
        vi.advanceTimersByTime(2500)
        const { notifications } = useUIStore.getState()
        expect(notifications).toHaveLength(1)
        expect(notifications[0].title).toBe('Second')
      })
    })
  })

  // ---------------------------------------------------------------------------
  // globalError
  // ---------------------------------------------------------------------------
  describe('globalError', () => {
    it('setGlobalError stores an error message', () => {
      useUIStore.getState().setGlobalError('Something went wrong')
      expect(useUIStore.getState().globalError).toBe('Something went wrong')
    })

    it('setGlobalError with null clears the error', () => {
      useUIStore.getState().setGlobalError('Some error')
      useUIStore.getState().setGlobalError(null)
      expect(useUIStore.getState().globalError).toBeNull()
    })

    it('setGlobalError overwrites a previous error message', () => {
      useUIStore.getState().setGlobalError('First error')
      useUIStore.getState().setGlobalError('Second error')
      expect(useUIStore.getState().globalError).toBe('Second error')
    })
  })
})
