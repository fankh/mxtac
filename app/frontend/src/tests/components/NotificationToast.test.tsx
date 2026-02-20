import { render, screen, fireEvent, act } from '@testing-library/react'
import { describe, it, expect, beforeEach } from 'vitest'
import { NotificationToast } from '../../components/shared/NotificationToast'
import { useUIStore } from '../../stores/uiStore'

function renderToast() {
  return render(<NotificationToast />)
}

describe('NotificationToast', () => {
  beforeEach(() => {
    useUIStore.setState({
      theme: 'light',
      sidebarCollapsed: false,
      notifications: [],
      globalError: null,
    })
  })

  // ---------------------------------------------------------------------------
  // Empty state
  // ---------------------------------------------------------------------------
  describe('empty state', () => {
    it('renders nothing when there are no notifications', () => {
      const { container } = renderToast()
      expect(container.firstChild).toBeNull()
    })

    it('returns null when notifications array is empty', () => {
      const { container } = renderToast()
      expect(container.childElementCount).toBe(0)
    })
  })

  // ---------------------------------------------------------------------------
  // Single notification rendering
  // ---------------------------------------------------------------------------
  describe('single notification', () => {
    it('renders the container when a notification is present', () => {
      useUIStore.setState({
        notifications: [{ id: '1', type: 'info', title: 'Hello' }],
      })
      renderToast()
      expect(screen.getByText('Hello')).toBeInTheDocument()
    })

    it('renders the notification title', () => {
      useUIStore.setState({
        notifications: [{ id: '1', type: 'info', title: 'Alert title' }],
      })
      renderToast()
      expect(screen.getByText('Alert title')).toBeInTheDocument()
    })

    it('renders the optional message when provided', () => {
      useUIStore.setState({
        notifications: [{ id: '1', type: 'success', title: 'Done', message: 'Saved successfully' }],
      })
      renderToast()
      expect(screen.getByText('Saved successfully')).toBeInTheDocument()
    })

    it('does not render a message element when message is absent', () => {
      useUIStore.setState({
        notifications: [{ id: '1', type: 'warning', title: 'No message' }],
      })
      renderToast()
      // Only one text node should be in the notification area — the title
      expect(screen.getByText('No message')).toBeInTheDocument()
      // No sibling message div
      const title = screen.getByText('No message')
      expect(title.nextElementSibling).toBeNull()
    })

    it('renders a close button with the × character', () => {
      useUIStore.setState({
        notifications: [{ id: '1', type: 'info', title: 'Closeable' }],
      })
      renderToast()
      expect(screen.getByRole('button')).toBeInTheDocument()
      expect(screen.getByRole('button')).toHaveTextContent('×')
    })
  })

  // ---------------------------------------------------------------------------
  // Notification types — CSS class mapping
  // ---------------------------------------------------------------------------
  describe('notification types', () => {
    const TYPE_CASES = [
      { type: 'info',    classes: ['border-blue', 'bg-blue-light', 'text-blue'] },
      { type: 'success', classes: ['border-status-ok', 'bg-status-ok-bg', 'text-status-ok-text'] },
      { type: 'warning', classes: ['border-status-warn', 'bg-status-warn-bg', 'text-status-warn-text'] },
      { type: 'error',   classes: ['border-crit-text', 'bg-crit-bg', 'text-crit-text'] },
    ] as const

    TYPE_CASES.forEach(({ type, classes }) => {
      describe(`type="${type}"`, () => {
        beforeEach(() => {
          useUIStore.setState({
            notifications: [{ id: '1', type, title: `${type} notification` }],
          })
        })

        classes.forEach((cls) => {
          it(`applies class "${cls}"`, () => {
            renderToast()
            const title = screen.getByText(`${type} notification`)
            // The type-specific classes sit on the wrapping card div (grandparent of title)
            const card = title.closest('div[class*="rounded-md"]')
            expect(card).not.toBeNull()
            expect(card!.className).toContain(cls)
          })
        })
      })
    })
  })

  // ---------------------------------------------------------------------------
  // Multiple notifications
  // ---------------------------------------------------------------------------
  describe('multiple notifications', () => {
    it('renders all notifications when multiple are present', () => {
      useUIStore.setState({
        notifications: [
          { id: '1', type: 'info',    title: 'First' },
          { id: '2', type: 'success', title: 'Second' },
          { id: '3', type: 'error',   title: 'Third' },
        ],
      })
      renderToast()
      expect(screen.getByText('First')).toBeInTheDocument()
      expect(screen.getByText('Second')).toBeInTheDocument()
      expect(screen.getByText('Third')).toBeInTheDocument()
    })

    it('renders the correct number of close buttons for multiple notifications', () => {
      useUIStore.setState({
        notifications: [
          { id: '1', type: 'info',    title: 'A' },
          { id: '2', type: 'warning', title: 'B' },
        ],
      })
      renderToast()
      expect(screen.getAllByRole('button')).toHaveLength(2)
    })

    it('renders notifications in order (first added appears first in DOM)', () => {
      useUIStore.setState({
        notifications: [
          { id: '1', type: 'info',  title: 'Alpha' },
          { id: '2', type: 'error', title: 'Beta' },
        ],
      })
      renderToast()
      const titles = screen.getAllByText(/Alpha|Beta/)
      expect(titles[0]).toHaveTextContent('Alpha')
      expect(titles[1]).toHaveTextContent('Beta')
    })

    it('renders each notification message independently', () => {
      useUIStore.setState({
        notifications: [
          { id: '1', type: 'info',    title: 'T1', message: 'Msg one' },
          { id: '2', type: 'success', title: 'T2', message: 'Msg two' },
        ],
      })
      renderToast()
      expect(screen.getByText('Msg one')).toBeInTheDocument()
      expect(screen.getByText('Msg two')).toBeInTheDocument()
    })

    it('mixed: renders message for notifications that have one and omits it for those that do not', () => {
      useUIStore.setState({
        notifications: [
          { id: '1', type: 'info',  title: 'With message',    message: 'Here it is' },
          { id: '2', type: 'error', title: 'Without message' },
        ],
      })
      renderToast()
      expect(screen.getByText('Here it is')).toBeInTheDocument()
      expect(screen.queryByText('Without message')!.nextElementSibling).toBeNull()
    })
  })

  // ---------------------------------------------------------------------------
  // Container layout
  // ---------------------------------------------------------------------------
  describe('container layout', () => {
    it('positions the container at bottom-right with fixed positioning', () => {
      useUIStore.setState({
        notifications: [{ id: '1', type: 'info', title: 'Test' }],
      })
      const { container } = renderToast()
      const wrapper = container.firstChild as HTMLElement
      expect(wrapper.className).toContain('fixed')
      expect(wrapper.className).toContain('bottom-4')
      expect(wrapper.className).toContain('right-4')
    })

    it('container has z-index class z-50 to appear above other content', () => {
      useUIStore.setState({
        notifications: [{ id: '1', type: 'info', title: 'Layered' }],
      })
      const { container } = renderToast()
      const wrapper = container.firstChild as HTMLElement
      expect(wrapper.className).toContain('z-50')
    })

    it('container stacks notifications in a column', () => {
      useUIStore.setState({
        notifications: [{ id: '1', type: 'info', title: 'Stack test' }],
      })
      const { container } = renderToast()
      const wrapper = container.firstChild as HTMLElement
      expect(wrapper.className).toContain('flex-col')
    })

    it('container has a fixed width of 320px', () => {
      useUIStore.setState({
        notifications: [{ id: '1', type: 'info', title: 'Width test' }],
      })
      const { container } = renderToast()
      const wrapper = container.firstChild as HTMLElement
      expect(wrapper.className).toContain('w-[320px]')
    })
  })

  // ---------------------------------------------------------------------------
  // Close button interaction
  // ---------------------------------------------------------------------------
  describe('close button', () => {
    it('clicking close removes that notification from the store', () => {
      useUIStore.setState({
        notifications: [{ id: '42', type: 'info', title: 'Remove me' }],
      })
      renderToast()
      fireEvent.click(screen.getByRole('button'))
      expect(useUIStore.getState().notifications).toHaveLength(0)
    })

    it('clicking close hides the dismissed notification from the UI', () => {
      useUIStore.setState({
        notifications: [{ id: '1', type: 'info', title: 'Gone soon' }],
      })
      const { rerender } = renderToast()
      fireEvent.click(screen.getByRole('button'))
      rerender(<NotificationToast />)
      expect(screen.queryByText('Gone soon')).not.toBeInTheDocument()
    })

    it('clicking close on one notification leaves the others intact', () => {
      useUIStore.setState({
        notifications: [
          { id: '1', type: 'info',  title: 'Keep' },
          { id: '2', type: 'error', title: 'Remove' },
        ],
      })
      renderToast()
      const buttons = screen.getAllByRole('button')
      // Second button belongs to the second notification
      fireEvent.click(buttons[1])
      expect(useUIStore.getState().notifications).toHaveLength(1)
      expect(useUIStore.getState().notifications[0].title).toBe('Keep')
    })

    it('after removing all notifications the component disappears', () => {
      useUIStore.setState({
        notifications: [{ id: '1', type: 'warning', title: 'Last one' }],
      })
      const { rerender, container } = renderToast()
      fireEvent.click(screen.getByRole('button'))
      rerender(<NotificationToast />)
      expect(container.firstChild).toBeNull()
    })

    it('close button calls removeNotification with the correct id', () => {
      useUIStore.setState({
        notifications: [
          { id: 'abc', type: 'info', title: 'A' },
          { id: 'xyz', type: 'info', title: 'B' },
        ],
      })
      renderToast()
      const buttons = screen.getAllByRole('button')
      // Click the first close button (id = 'abc')
      fireEvent.click(buttons[0])
      const remaining = useUIStore.getState().notifications
      expect(remaining).toHaveLength(1)
      expect(remaining[0].id).toBe('xyz')
    })
  })

  // ---------------------------------------------------------------------------
  // Live store updates
  // ---------------------------------------------------------------------------
  describe('live store updates', () => {
    it('renders newly added notifications after a store update', () => {
      const { rerender } = renderToast()
      expect(screen.queryByText('New alert')).not.toBeInTheDocument()

      act(() => {
        useUIStore.setState({
          notifications: [{ id: '1', type: 'info', title: 'New alert' }],
        })
      })
      rerender(<NotificationToast />)
      expect(screen.getByText('New alert')).toBeInTheDocument()
    })

    it('transitions from empty to visible when first notification arrives', () => {
      const { container, rerender } = renderToast()
      expect(container.firstChild).toBeNull()

      act(() => {
        useUIStore.setState({
          notifications: [{ id: '1', type: 'success', title: 'Appeared!' }],
        })
      })
      rerender(<NotificationToast />)
      expect(screen.getByText('Appeared!')).toBeInTheDocument()
    })
  })
})
