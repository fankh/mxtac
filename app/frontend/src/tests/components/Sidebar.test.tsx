// vi.mock is hoisted before imports
vi.mock('../../components/shared/MfaSetupModal', () => ({
  MfaSetupModal: ({ onClose }: { onClose: () => void }) => (
    <div data-testid="mfa-setup-modal">
      <button onClick={onClose}>Close MFA Modal</button>
    </div>
  ),
}))

import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import { describe, it, expect, beforeEach, vi } from 'vitest'
import { Link, MemoryRouter, useLocation } from 'react-router-dom'
import { Sidebar } from '../../components/layout/Sidebar'
import { useUIStore } from '../../stores/uiStore'
import { useAuthStore } from '../../stores/authStore'
import { KYRA_MDR_URL } from '../../lib/links'

const NAV_ITEMS = [
  { label: 'Overview', href: '/' },
  { label: 'Detections', href: '/detections' },
  { label: 'Incidents', href: '/incidents' },
  { label: 'Hunt', href: '/hunt' },
  { label: 'ATT&CK Coverage', href: '/coverage' },
  { label: 'Sigma Rules', href: '/rules' },
  { label: 'Sources', href: '/sources' },
  { label: 'Settings', href: '/settings' },
]

function renderSidebar(initialPath = '/') {
  return render(
    <MemoryRouter initialEntries={[initialPath]}>
      <Sidebar />
    </MemoryRouter>,
  )
}

/** The nav link for a label; the accessible name also holds when the sidebar is collapsed. */
const navLink = (label: string) => screen.getByTitle(label)

function LocationProbe() {
  return <span data-testid="location">{useLocation().pathname}</span>
}

/** The sidebar next to a link the page itself would render, and the current path. */
function renderWithPage(initialPath = '/') {
  return render(
    <MemoryRouter initialEntries={[initialPath]}>
      <Sidebar />
      <Link to="/incidents">Page link to incidents</Link>
      <LocationProbe />
    </MemoryRouter>,
  )
}

const menuButton = () => screen.getByRole('button', { name: 'Open navigation', hidden: true })
const drawer = () => screen.getByRole('dialog', { name: 'Main navigation' })
const queryDrawer = () => screen.queryByRole('dialog', { name: 'Main navigation' })

function openDrawer() {
  fireEvent.click(menuButton())
  return within(drawer())
}

describe('Sidebar', () => {
  const logout = vi.fn().mockResolvedValue(undefined)

  beforeEach(() => {
    logout.mockClear()
    useUIStore.setState({
      theme: 'light',
      sidebarCollapsed: false,
      notifications: [],
      showShortcutsModal: false,
    })
    useAuthStore.setState({ user: { email: 'analyst@mxtac.local', role: 'analyst' }, logout })
  })

  describe('navigation', () => {
    it('is a landmark named "Main navigation"', () => {
      renderSidebar()
      expect(screen.getByRole('complementary', { name: 'Main navigation' })).toBeInTheDocument()
    })

    it.each(NAV_ITEMS)('links "$label" to $href', ({ label, href }) => {
      renderSidebar()
      expect(screen.getByRole('link', { name: label })).toHaveAttribute('href', href)
    })

    it('has no links other than the nav items and the KYRA MDR link', () => {
      renderSidebar()
      expect(screen.getAllByRole('link')).toHaveLength(NAV_ITEMS.length + 1)
    })

    it('shows the section titles', () => {
      renderSidebar()
      for (const title of ['Monitor', 'Investigate', 'Configure']) {
        expect(screen.getByText(title)).toBeInTheDocument()
      }
    })

    it('marks only the link for the current route as the current page', () => {
      renderSidebar('/detections')
      expect(navLink('Detections')).toHaveAttribute('aria-current', 'page')
      expect(navLink('Overview')).not.toHaveAttribute('aria-current')
      expect(navLink('Incidents')).not.toHaveAttribute('aria-current')
    })

    it('marks Overview as current only on the exact root path', () => {
      renderSidebar('/')
      expect(navLink('Overview')).toHaveAttribute('aria-current', 'page')
    })
  })

  describe('KYRA MDR link', () => {
    it('opens the KYRA MDR site in a new tab without leaking the opener', () => {
      renderSidebar()
      const link = screen.getByRole('link', { name: /KYRA MDR/ })
      expect(link).toHaveAttribute('href', KYRA_MDR_URL)
      expect(link).toHaveAttribute('target', '_blank')
      expect(link.getAttribute('rel')).toContain('noopener')
      expect(link).toHaveTextContent(/managed service/i)
    })

    it('stays available as an icon link when the sidebar is collapsed', () => {
      useUIStore.setState({ sidebarCollapsed: true })
      renderSidebar()
      const link = screen.getByTitle(/^KYRA MDR/)
      expect(link).toHaveAttribute('href', KYRA_MDR_URL)
      expect(link).toHaveAttribute('target', '_blank')
      expect(link.getAttribute('rel')).toContain('noopener')
    })
  })

  describe('collapse', () => {
    it('hides labels, section titles and the brand text when collapsed, but keeps every link', () => {
      renderSidebar()
      fireEvent.click(screen.getByTitle('Collapse sidebar'))

      expect(useUIStore.getState().sidebarCollapsed).toBe(true)
      expect(screen.queryByText('Detections')).not.toBeInTheDocument()
      expect(screen.queryByText('Monitor')).not.toBeInTheDocument()
      expect(screen.queryByText('MxTac')).not.toBeInTheDocument()
      for (const { label, href } of NAV_ITEMS) {
        expect(navLink(label)).toHaveAttribute('href', href)
      }
    })

    it('expands again from the collapsed state', () => {
      useUIStore.setState({ sidebarCollapsed: true })
      renderSidebar()
      fireEvent.click(screen.getByTitle('Expand sidebar'))

      expect(useUIStore.getState().sidebarCollapsed).toBe(false)
      expect(screen.getByText('MxTac')).toBeInTheDocument()
      expect(screen.getByTitle('Collapse sidebar')).toBeInTheDocument()
    })
  })

  describe('mobile drawer', () => {
    it('is closed at first: only the menu button is rendered', () => {
      renderWithPage()
      expect(menuButton()).toHaveAttribute('aria-expanded', 'false')
      expect(queryDrawer()).not.toBeInTheDocument()
    })

    it('opens from the menu button with every nav link and the KYRA MDR card', () => {
      renderWithPage('/detections')
      const inDrawer = openDrawer()

      expect(menuButton()).toHaveAttribute('aria-expanded', 'true')
      for (const { label, href } of NAV_ITEMS) {
        expect(inDrawer.getByRole('link', { name: label })).toHaveAttribute('href', href)
      }
      expect(inDrawer.getByRole('link', { name: 'Detections' })).toHaveAttribute('aria-current', 'page')
      const kyra = inDrawer.getByRole('link', { name: /KYRA MDR/ })
      expect(kyra).toHaveAttribute('href', KYRA_MDR_URL)
      expect(kyra).toHaveTextContent(/managed service/i)
    })

    it('keeps the account, theme and sign-out controls, without the collapse button', () => {
      renderWithPage()
      const inDrawer = openDrawer()

      expect(inDrawer.getByText('analyst@mxtac.local')).toBeInTheDocument()
      expect(inDrawer.getByTitle('analyst@mxtac.local: account security')).toBeInTheDocument()
      expect(inDrawer.getByTitle('Keyboard shortcuts')).toBeInTheDocument()
      expect(inDrawer.queryByTitle('Collapse sidebar')).not.toBeInTheDocument()

      fireEvent.click(inDrawer.getByTitle('Switch to dark mode'))
      expect(useUIStore.getState().theme).toBe('dark')
      expect(drawer()).toBeInTheDocument()

      fireEvent.click(inDrawer.getByTitle('Sign out'))
      expect(logout).toHaveBeenCalledTimes(1)
    })

    it('shows labels in the drawer even when the desktop sidebar is collapsed', () => {
      useUIStore.setState({ sidebarCollapsed: true })
      renderWithPage()
      const inDrawer = openDrawer()
      expect(inDrawer.getByText('Detections')).toBeInTheDocument()
      expect(inDrawer.getByText('Monitor')).toBeInTheDocument()
    })

    it('closes when a nav link is followed, and the route changes', async () => {
      renderWithPage('/')
      fireEvent.click(openDrawer().getByRole('link', { name: 'Hunt' }))

      expect(screen.getByTestId('location')).toHaveTextContent('/hunt')
      await waitFor(() => expect(queryDrawer()).not.toBeInTheDocument())
      expect(menuButton()).toHaveAttribute('aria-expanded', 'false')
    })

    it('closes when the link of the current page is followed', async () => {
      renderWithPage('/hunt')
      fireEvent.click(openDrawer().getByRole('link', { name: 'Hunt' }))
      await waitFor(() => expect(queryDrawer()).not.toBeInTheDocument())
    })

    it('closes when the route changes for another reason', async () => {
      renderWithPage('/')
      openDrawer()
      fireEvent.click(screen.getByText('Page link to incidents'))

      expect(screen.getByTestId('location')).toHaveTextContent('/incidents')
      await waitFor(() => expect(queryDrawer()).not.toBeInTheDocument())
    })

    it('closes on Escape and returns focus to the menu button', async () => {
      renderWithPage()
      openDrawer()
      fireEvent.keyDown(drawer(), { key: 'Escape' })

      await waitFor(() => expect(queryDrawer()).not.toBeInTheDocument())
      await waitFor(() => expect(menuButton()).toHaveFocus())
    })

    it('closes from its close button and returns focus to the menu button', async () => {
      renderWithPage()
      fireEvent.click(openDrawer().getByRole('button', { name: 'Close' }))

      await waitFor(() => expect(queryDrawer()).not.toBeInTheDocument())
      await waitFor(() => expect(menuButton()).toHaveFocus())
    })

    it('closes and opens the MFA modal from the account button', async () => {
      renderWithPage()
      fireEvent.click(openDrawer().getByTitle('analyst@mxtac.local: account security'))

      expect(screen.getByTestId('mfa-setup-modal')).toBeInTheDocument()
      await waitFor(() => expect(queryDrawer()).not.toBeInTheDocument())
    })

    it('closes and opens the keyboard shortcuts modal', async () => {
      renderWithPage()
      fireEvent.click(openDrawer().getByTitle('Keyboard shortcuts'))

      expect(useUIStore.getState().showShortcutsModal).toBe(true)
      await waitFor(() => expect(queryDrawer()).not.toBeInTheDocument())
    })
  })

  describe('theme toggle', () => {
    it('switches from light to dark and sets the dark class on <html>', () => {
      renderSidebar()
      fireEvent.click(screen.getByTitle('Switch to dark mode'))

      expect(useUIStore.getState().theme).toBe('dark')
      expect(document.documentElement).toHaveClass('dark')
      expect(screen.getByTitle('Switch to light mode')).toBeInTheDocument()
    })

    it('switches from dark back to light and removes the dark class', () => {
      useUIStore.getState().setTheme('dark')
      renderSidebar()
      fireEvent.click(screen.getByTitle('Switch to light mode'))

      expect(useUIStore.getState().theme).toBe('light')
      expect(document.documentElement).not.toHaveClass('dark')
    })
  })

  describe('account', () => {
    it('shows the signed-in user, role and initials', () => {
      renderSidebar()
      expect(screen.getByText('analyst@mxtac.local')).toBeInTheDocument()
      expect(screen.getByText('analyst')).toBeInTheDocument()
      expect(screen.getByText('AN')).toBeInTheDocument()
    })

    it('shows "Account" when no user is loaded', () => {
      useAuthStore.setState({ user: null })
      renderSidebar()
      expect(screen.getByText('Account')).toBeInTheDocument()
      expect(screen.getByTitle('Account security')).toBeInTheDocument()
    })

    it('opens and closes the MFA setup modal from the account button', () => {
      renderSidebar()
      expect(screen.queryByTestId('mfa-setup-modal')).not.toBeInTheDocument()

      fireEvent.click(screen.getByTitle('analyst@mxtac.local: account security'))
      expect(screen.getByTestId('mfa-setup-modal')).toBeInTheDocument()

      fireEvent.click(screen.getByText('Close MFA Modal'))
      expect(screen.queryByTestId('mfa-setup-modal')).not.toBeInTheDocument()
    })

    it('signs out', () => {
      renderSidebar()
      fireEvent.click(screen.getByTitle('Sign out'))
      expect(logout).toHaveBeenCalledTimes(1)
    })

    it('opens the keyboard shortcuts modal', () => {
      renderSidebar()
      fireEvent.click(screen.getByTitle('Keyboard shortcuts'))
      expect(useUIStore.getState().showShortcutsModal).toBe(true)
    })
  })
})
