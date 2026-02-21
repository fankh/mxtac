import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { TopBar } from '../../components/layout/TopBar'
import { useAlertStream } from '../../hooks/useAlertStream'
import type { ConnectionState } from '../../hooks/useAlertStream'
import { useUIStore } from '../../stores/uiStore'

// ---------------------------------------------------------------------------
// Mock useAlertStream so TopBar renders without a real WebSocket connection
// ---------------------------------------------------------------------------

vi.mock('../../hooks/useAlertStream')

const mockUseAlertStream = vi.mocked(useAlertStream)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function renderTopBar(crumb: string, updatedAt?: string) {
  return render(<TopBar crumb={crumb} updatedAt={updatedAt} />)
}

// ---------------------------------------------------------------------------
// TopBar
// ---------------------------------------------------------------------------

describe('TopBar', () => {
  beforeEach(() => {
    // Default to "connected" state unless overridden per-test
    mockUseAlertStream.mockReturnValue('connected')
    // Default to dark theme so the toggle button shows "Switch to light mode"
    useUIStore.setState({ theme: 'dark' })
  })

  // -------------------------------------------------------------------------
  // Breadcrumb
  // -------------------------------------------------------------------------
  describe('Breadcrumb', () => {
    it('renders the "MxTac" root label', () => {
      renderTopBar('Dashboard')
      expect(screen.getByText('MxTac')).toBeInTheDocument()
    })

    it('renders the "/" separator', () => {
      renderTopBar('Dashboard')
      expect(screen.getByText('/')).toBeInTheDocument()
    })

    it('renders the crumb label', () => {
      renderTopBar('Dashboard')
      expect(screen.getByText('Dashboard')).toBeInTheDocument()
    })

    it('renders different crumb values', () => {
      const crumbs = [
        'Overview',
        'Detections',
        'ATT&CK Coverage',
        'Sigma Rules',
        'Incidents',
        'Threat Intel',
        'Integrations',
        'Admin',
      ]
      crumbs.forEach(crumb => {
        const { unmount } = renderTopBar(crumb)
        expect(screen.getByText(crumb)).toBeInTheDocument()
        unmount()
      })
    })

    it('renders a crumb with special characters', () => {
      renderTopBar('ATT&CK Explorer')
      expect(screen.getByText('ATT&CK Explorer')).toBeInTheDocument()
    })

    it('renders a crumb with a long label', () => {
      const longCrumb = 'Very Long Page Name That Spans Multiple Words'
      renderTopBar(longCrumb)
      expect(screen.getByText(longCrumb)).toBeInTheDocument()
    })

    it('renders a crumb with a single character', () => {
      renderTopBar('X')
      expect(screen.getByText('X')).toBeInTheDocument()
    })

    it('renders a crumb containing numbers', () => {
      renderTopBar('Rule #42')
      expect(screen.getByText('Rule #42')).toBeInTheDocument()
    })
  })

  // -------------------------------------------------------------------------
  // Updated timestamp
  // -------------------------------------------------------------------------
  describe('updatedAt timestamp', () => {
    it('shows "Updated {value}" when updatedAt is provided', () => {
      renderTopBar('Dashboard', '2 min ago')
      expect(screen.getByText('Updated 2 min ago')).toBeInTheDocument()
    })

    it('does not render timestamp when updatedAt is omitted', () => {
      renderTopBar('Dashboard')
      expect(screen.queryByText(/Updated/)).not.toBeInTheDocument()
    })

    it('does not render timestamp when updatedAt is undefined', () => {
      renderTopBar('Dashboard', undefined)
      expect(screen.queryByText(/Updated/)).not.toBeInTheDocument()
    })

    it('shows timestamp with relative time format', () => {
      renderTopBar('Detections', 'just now')
      expect(screen.getByText('Updated just now')).toBeInTheDocument()
    })

    it('shows timestamp with absolute date string', () => {
      renderTopBar('Detections', '2024-01-15 14:30 UTC')
      expect(screen.getByText('Updated 2024-01-15 14:30 UTC')).toBeInTheDocument()
    })

    it('shows timestamp with "X minutes ago" format', () => {
      renderTopBar('Overview', '5 minutes ago')
      expect(screen.getByText('Updated 5 minutes ago')).toBeInTheDocument()
    })
  })

  // -------------------------------------------------------------------------
  // Refresh button
  // -------------------------------------------------------------------------
  describe('Refresh button', () => {
    it('renders the Refresh button', () => {
      renderTopBar('Dashboard')
      expect(screen.getByTitle('Refresh')).toBeInTheDocument()
    })

    it('Refresh button is a <button> element', () => {
      renderTopBar('Dashboard')
      expect(screen.getByTitle('Refresh').tagName).toBe('BUTTON')
    })

    it('Refresh button contains the ↻ icon', () => {
      renderTopBar('Dashboard')
      expect(screen.getByTitle('Refresh')).toHaveTextContent('↻')
    })

    it('Refresh button is always rendered regardless of updatedAt', () => {
      const { unmount } = renderTopBar('Dashboard')
      expect(screen.getByTitle('Refresh')).toBeInTheDocument()
      unmount()

      renderTopBar('Dashboard', '2 min ago')
      expect(screen.getByTitle('Refresh')).toBeInTheDocument()
    })
  })

  // -------------------------------------------------------------------------
  // Notifications button
  // -------------------------------------------------------------------------
  describe('Notifications button', () => {
    it('renders the Notifications button', () => {
      renderTopBar('Dashboard')
      expect(screen.getByTitle('Notifications')).toBeInTheDocument()
    })

    it('Notifications button is a <button> element', () => {
      renderTopBar('Dashboard')
      expect(screen.getByTitle('Notifications').tagName).toBe('BUTTON')
    })

    it('Notifications button contains the 🔔 icon', () => {
      renderTopBar('Dashboard')
      expect(screen.getByTitle('Notifications')).toHaveTextContent('🔔')
    })

    it('renders the notification alert indicator dot', () => {
      renderTopBar('Dashboard')
      // The dot is a sibling <span> inside the .relative container
      const notifWrapper = screen.getByTitle('Notifications').closest('.relative')
      expect(notifWrapper).not.toBeNull()
      expect(notifWrapper!.querySelector('.bg-crit-text')).toBeInTheDocument()
    })

    it('alert indicator dot is always visible (static badge)', () => {
      renderTopBar('Dashboard', '3 min ago')
      const notifWrapper = screen.getByTitle('Notifications').closest('.relative')
      expect(notifWrapper!.querySelector('.bg-crit-text')).toBeInTheDocument()
    })
  })

  // -------------------------------------------------------------------------
  // Live connection indicator
  // -------------------------------------------------------------------------
  describe('Live connection indicator', () => {
    const states: ConnectionState[] = ['connected', 'reconnecting', 'disconnected']

    it('renders a live dot for all connection states', () => {
      states.forEach(state => {
        mockUseAlertStream.mockReturnValue(state)
        const { unmount } = renderTopBar('Dashboard')
        // Each state renders a span with a title attribute
        expect(screen.getByTitle(
          state === 'connected'    ? 'Live — connected' :
          state === 'reconnecting' ? 'Reconnecting…'    : 'Disconnected'
        )).toBeInTheDocument()
        unmount()
      })
    })

    it('shows "Live — connected" title when connected', () => {
      mockUseAlertStream.mockReturnValue('connected')
      renderTopBar('Dashboard')
      expect(screen.getByTitle('Live — connected')).toBeInTheDocument()
    })

    it('shows "Reconnecting…" title when reconnecting', () => {
      mockUseAlertStream.mockReturnValue('reconnecting')
      renderTopBar('Dashboard')
      expect(screen.getByTitle('Reconnecting…')).toBeInTheDocument()
    })

    it('shows "Disconnected" title when disconnected', () => {
      mockUseAlertStream.mockReturnValue('disconnected')
      renderTopBar('Dashboard')
      expect(screen.getByTitle('Disconnected')).toBeInTheDocument()
    })

    it('connected dot has ping animation class', () => {
      mockUseAlertStream.mockReturnValue('connected')
      const { container } = renderTopBar('Dashboard')
      const liveWrapper = screen.getByTitle('Live — connected')
      expect(liveWrapper.querySelector('.animate-ping')).toBeInTheDocument()
    })

    it('reconnecting dot has pulse animation class', () => {
      mockUseAlertStream.mockReturnValue('reconnecting')
      renderTopBar('Dashboard')
      const liveWrapper = screen.getByTitle('Reconnecting…')
      expect(liveWrapper.querySelector('.animate-pulse')).toBeInTheDocument()
    })

    it('disconnected dot has no animation class', () => {
      mockUseAlertStream.mockReturnValue('disconnected')
      renderTopBar('Dashboard')
      const liveWrapper = screen.getByTitle('Disconnected')
      expect(liveWrapper.querySelector('.animate-ping')).not.toBeInTheDocument()
      expect(liveWrapper.querySelector('.animate-pulse')).not.toBeInTheDocument()
    })

    it('connected dot uses status-ok color', () => {
      mockUseAlertStream.mockReturnValue('connected')
      renderTopBar('Dashboard')
      const liveWrapper = screen.getByTitle('Live — connected')
      expect(liveWrapper.querySelector('.bg-status-ok')).toBeInTheDocument()
    })

    it('reconnecting dot uses status-warn color', () => {
      mockUseAlertStream.mockReturnValue('reconnecting')
      renderTopBar('Dashboard')
      const liveWrapper = screen.getByTitle('Reconnecting…')
      expect(liveWrapper.querySelector('.bg-status-warn')).toBeInTheDocument()
    })

    it('disconnected dot uses text-muted color', () => {
      mockUseAlertStream.mockReturnValue('disconnected')
      renderTopBar('Dashboard')
      const liveWrapper = screen.getByTitle('Disconnected')
      expect(liveWrapper.querySelector('.bg-text-muted')).toBeInTheDocument()
    })

    it('only one live dot is rendered', () => {
      mockUseAlertStream.mockReturnValue('connected')
      const { container } = renderTopBar('Dashboard')
      const titles = ['Live — connected', 'Reconnecting…', 'Disconnected']
      const dots = titles.flatMap(t =>
        Array.from(container.querySelectorAll(`[title="${t}"]`))
      )
      expect(dots).toHaveLength(1)
    })
  })

  // -------------------------------------------------------------------------
  // Layout structure
  // -------------------------------------------------------------------------
  describe('Layout structure', () => {
    it('renders a <header> as the root element', () => {
      const { container } = renderTopBar('Dashboard')
      expect(container.querySelector('header')).toBeInTheDocument()
    })

    it('renders all required elements together', () => {
      renderTopBar('Detections')
      expect(screen.getByText('MxTac')).toBeInTheDocument()
      expect(screen.getByText('/')).toBeInTheDocument()
      expect(screen.getByText('Detections')).toBeInTheDocument()
      expect(screen.getByTitle('Refresh')).toBeInTheDocument()
      expect(screen.getByTitle('Notifications')).toBeInTheDocument()
      expect(screen.getByTitle('Live — connected')).toBeInTheDocument()
    })

    it('renders only one Refresh button', () => {
      const { container } = renderTopBar('Dashboard')
      expect(container.querySelectorAll('[title="Refresh"]')).toHaveLength(1)
    })

    it('renders only one Notifications button', () => {
      const { container } = renderTopBar('Dashboard')
      expect(container.querySelectorAll('[title="Notifications"]')).toHaveLength(1)
    })

    it('renders all required elements including theme toggle', () => {
      renderTopBar('Detections')
      expect(screen.getByTitle('Refresh')).toBeInTheDocument()
      expect(screen.getByTitle('Notifications')).toBeInTheDocument()
      expect(screen.getByTitle(/Switch to (light|dark) mode/)).toBeInTheDocument()
    })
  })

  // -------------------------------------------------------------------------
  // Theme toggle
  // -------------------------------------------------------------------------
  describe('Theme toggle', () => {
    it('renders the theme toggle button', () => {
      renderTopBar('Dashboard')
      expect(screen.getByTitle(/Switch to (light|dark) mode/)).toBeInTheDocument()
    })

    it('shows "Switch to light mode" when dark theme is active', () => {
      useUIStore.setState({ theme: 'dark' })
      renderTopBar('Dashboard')
      expect(screen.getByTitle('Switch to light mode')).toBeInTheDocument()
    })

    it('shows "Switch to dark mode" when light theme is active', () => {
      useUIStore.setState({ theme: 'light' })
      renderTopBar('Dashboard')
      expect(screen.getByTitle('Switch to dark mode')).toBeInTheDocument()
    })

    it('theme toggle button is a <button> element', () => {
      renderTopBar('Dashboard')
      expect(screen.getByTitle(/Switch to (light|dark) mode/).tagName).toBe('BUTTON')
    })

    it('clicking the toggle button switches from dark to light', () => {
      useUIStore.setState({ theme: 'dark' })
      renderTopBar('Dashboard')
      fireEvent.click(screen.getByTitle('Switch to light mode'))
      expect(useUIStore.getState().theme).toBe('light')
    })

    it('clicking the toggle button switches from light to dark', () => {
      useUIStore.setState({ theme: 'light' })
      renderTopBar('Dashboard')
      fireEvent.click(screen.getByTitle('Switch to dark mode'))
      expect(useUIStore.getState().theme).toBe('dark')
    })

    it('clicking the toggle applies data-theme to documentElement', () => {
      useUIStore.setState({ theme: 'dark' })
      renderTopBar('Dashboard')
      fireEvent.click(screen.getByTitle('Switch to light mode'))
      expect(document.documentElement.getAttribute('data-theme')).toBe('light')
    })

    it('renders only one theme toggle button', () => {
      const { container } = renderTopBar('Dashboard')
      const matches = container.querySelectorAll('[title="Switch to light mode"], [title="Switch to dark mode"]')
      expect(matches).toHaveLength(1)
    })
  })
})
