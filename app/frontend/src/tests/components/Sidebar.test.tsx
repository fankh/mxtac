import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, beforeEach } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { Sidebar } from '../../components/layout/Sidebar'
import { useUIStore } from '../../stores/uiStore'

function renderSidebar(initialPath = '/') {
  return render(
    <MemoryRouter initialEntries={[initialPath]}>
      <Sidebar />
    </MemoryRouter>,
  )
}

describe('Sidebar', () => {
  beforeEach(() => {
    useUIStore.setState({
      theme: 'light',
      sidebarCollapsed: false,
      notifications: [],
      globalError: null,
    })
  })

  // ---------------------------------------------------------------------------
  // Logo
  // ---------------------------------------------------------------------------
  describe('Logo', () => {
    it('renders the "M" logo mark', () => {
      renderSidebar()
      expect(screen.getByText('M')).toBeInTheDocument()
    })
  })

  // ---------------------------------------------------------------------------
  // Navigation links
  // ---------------------------------------------------------------------------
  describe('Navigation links', () => {
    const NAV_ITEMS = [
      { label: 'Overview',        href: '/' },
      { label: 'Detections',      href: '/detections' },
      { label: 'Event Hunt',      href: '/hunt' },
      { label: 'ATT&CK Coverage', href: '/attack' },
      { label: 'Sigma Rules',     href: '/rules' },
      { label: 'Incidents',       href: '/incidents' },
      { label: 'Threat Intel',    href: '/intel' },
      { label: 'Assets',          href: '/assets' },
      { label: 'Reports',         href: '/reports' },
      { label: 'Integrations',    href: '/integrations' },
      { label: 'Admin',           href: '/admin' },
    ]

    it('renders exactly 11 nav links', () => {
      renderSidebar()
      const nav = screen.getByRole('navigation')
      expect(nav.querySelectorAll('a')).toHaveLength(11)
    })

    NAV_ITEMS.forEach(({ label, href }) => {
      it(`"${label}" link points to "${href}"`, () => {
        renderSidebar()
        const link = screen.getByTitle(label)
        expect(link).toBeInTheDocument()
        expect(link).toHaveAttribute('href', href)
      })
    })

    it('active route link receives active styles', () => {
      renderSidebar('/detections')
      expect(screen.getByTitle('Detections').className).toContain('bg-blue-light')
      expect(screen.getByTitle('Detections').className).toContain('text-blue')
    })

    it('inactive links receive muted styles', () => {
      renderSidebar('/detections')
      expect(screen.getByTitle('Overview').className).not.toContain('bg-blue-light')
      expect(screen.getByTitle('Overview').className).toContain('text-text-muted')
    })

    it('Overview link is inactive when visiting a sub-route (end matching)', () => {
      // Because `end={true}` is applied only to the root link, "/detections"
      // must not mark "/" as active.
      renderSidebar('/detections')
      expect(screen.getByTitle('Overview').className).not.toContain('bg-blue-light')
    })

    it('Overview link is active on exact "/" path', () => {
      renderSidebar('/')
      expect(screen.getByTitle('Overview').className).toContain('bg-blue-light')
    })

    it('each nav link has a descriptive title attribute', () => {
      renderSidebar()
      NAV_ITEMS.forEach(({ label }) => {
        expect(screen.getByTitle(label)).toBeInTheDocument()
      })
    })
  })

  // ---------------------------------------------------------------------------
  // Theme toggle
  // ---------------------------------------------------------------------------
  describe('Theme toggle', () => {
    it('shows the theme button with current light theme label', () => {
      renderSidebar()
      expect(screen.getByTitle('Theme: light')).toBeInTheDocument()
    })

    it('shows the theme button with dark theme label when dark is active', () => {
      useUIStore.setState({ theme: 'dark' })
      renderSidebar()
      expect(screen.getByTitle('Theme: dark')).toBeInTheDocument()
    })

    it('shows the theme button with matrix theme label when matrix is active', () => {
      useUIStore.setState({ theme: 'matrix' })
      renderSidebar()
      expect(screen.getByTitle('Theme: matrix')).toBeInTheDocument()
    })

    it('theme menu is hidden by default', () => {
      renderSidebar()
      expect(screen.queryByText('Light')).not.toBeInTheDocument()
      expect(screen.queryByText('Dark')).not.toBeInTheDocument()
      expect(screen.queryByText('Matrix')).not.toBeInTheDocument()
    })

    it('clicking the theme button opens the menu with all 3 options', () => {
      renderSidebar()
      fireEvent.click(screen.getByTitle('Theme: light'))
      expect(screen.getByText('Light')).toBeInTheDocument()
      expect(screen.getByText('Dark')).toBeInTheDocument()
      expect(screen.getByText('Matrix')).toBeInTheDocument()
    })

    it('clicking a theme option updates the store theme', () => {
      renderSidebar()
      fireEvent.click(screen.getByTitle('Theme: light'))
      fireEvent.click(screen.getByText('Dark'))
      expect(useUIStore.getState().theme).toBe('dark')
    })

    it('selecting a theme applies data-theme to the document element', () => {
      renderSidebar()
      fireEvent.click(screen.getByTitle('Theme: light'))
      fireEvent.click(screen.getByText('Matrix'))
      expect(document.documentElement.getAttribute('data-theme')).toBe('matrix')
    })

    it('clicking a theme option closes the menu', () => {
      renderSidebar()
      fireEvent.click(screen.getByTitle('Theme: light'))
      fireEvent.click(screen.getByText('Dark'))
      expect(screen.queryByText('Light')).not.toBeInTheDocument()
    })

    it('clicking outside the theme menu closes it', () => {
      renderSidebar()
      fireEvent.click(screen.getByTitle('Theme: light'))
      expect(screen.getByText('Light')).toBeInTheDocument()

      fireEvent.mouseDown(document.body)
      expect(screen.queryByText('Light')).not.toBeInTheDocument()
    })

    it('clicking inside the theme menu does not close it', () => {
      renderSidebar()
      fireEvent.click(screen.getByTitle('Theme: light'))

      // mousedown inside the menu — should not close
      fireEvent.mouseDown(screen.getByText('Light'))
      expect(screen.getByText('Light')).toBeInTheDocument()
    })

    it('clicking the theme button again toggles the menu closed', () => {
      renderSidebar()
      fireEvent.click(screen.getByTitle('Theme: light'))
      expect(screen.getByText('Light')).toBeInTheDocument()

      fireEvent.click(screen.getByTitle('Theme: light'))
      expect(screen.queryByText('Light')).not.toBeInTheDocument()
    })

    it('the currently active theme option receives highlight styles', () => {
      useUIStore.setState({ theme: 'dark' })
      renderSidebar()
      fireEvent.click(screen.getByTitle('Theme: dark'))

      // The "Dark" button should have the active class
      const darkBtn = screen.getByText('Dark').closest('button')!
      expect(darkBtn.className).toContain('text-blue')
    })
  })

  // ---------------------------------------------------------------------------
  // Bottom controls
  // ---------------------------------------------------------------------------
  describe('Bottom controls', () => {
    it('renders the Help button', () => {
      renderSidebar()
      expect(screen.getByTitle('Help')).toBeInTheDocument()
    })

    it('renders the Settings button', () => {
      renderSidebar()
      expect(screen.getByTitle('Settings')).toBeInTheDocument()
    })

    it('renders the user avatar with KH initials', () => {
      renderSidebar()
      expect(screen.getByText('KH')).toBeInTheDocument()
    })
  })
})
