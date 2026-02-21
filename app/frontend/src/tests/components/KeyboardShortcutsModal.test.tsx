/**
 * Tests for KeyboardShortcutsModal
 *
 * Covers:
 *  - Renders dialog with heading
 *  - Displays all shortcut groups (Navigation, Actions)
 *  - Displays all expected shortcut descriptions
 *  - Displays key labels as <kbd> elements
 *  - Close button calls closeShortcutsModal
 *  - Backdrop click calls closeShortcutsModal
 *  - Escape key closes the modal
 *  - aria attributes for accessibility
 */

import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, beforeEach } from 'vitest'
import { KeyboardShortcutsModal } from '../../components/shared/KeyboardShortcutsModal'
import { useUIStore } from '../../stores/uiStore'

function renderModal() {
  return render(<KeyboardShortcutsModal />)
}

describe('KeyboardShortcutsModal', () => {
  beforeEach(() => {
    useUIStore.setState({ showShortcutsModal: true })
  })

  // ── Heading & role ───────────────────────────────────────────────────────────

  it('renders a dialog element with aria-label "Keyboard Shortcuts"', () => {
    renderModal()
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect(screen.getByRole('dialog')).toHaveAttribute('aria-label', 'Keyboard Shortcuts')
  })

  it('displays the "Keyboard Shortcuts" heading text', () => {
    renderModal()
    expect(screen.getByText('Keyboard Shortcuts')).toBeInTheDocument()
  })

  // ── Shortcut groups ──────────────────────────────────────────────────────────

  it('renders the Navigation group heading', () => {
    renderModal()
    expect(screen.getByText('Navigation')).toBeInTheDocument()
  })

  it('renders the Actions group heading', () => {
    renderModal()
    expect(screen.getByText('Actions')).toBeInTheDocument()
  })

  // ── Navigation shortcuts ─────────────────────────────────────────────────────

  it('shows "Go to Dashboard" shortcut', () => {
    renderModal()
    expect(screen.getByText('Go to Dashboard')).toBeInTheDocument()
  })

  it('shows "Go to Detections" shortcut', () => {
    renderModal()
    expect(screen.getByText('Go to Detections')).toBeInTheDocument()
  })

  it('shows "Go to Rules" shortcut', () => {
    renderModal()
    expect(screen.getByText('Go to Rules')).toBeInTheDocument()
  })

  it('shows "Go to Connectors" shortcut', () => {
    renderModal()
    expect(screen.getByText('Go to Connectors')).toBeInTheDocument()
  })

  it('shows "Go to Incidents" shortcut', () => {
    renderModal()
    expect(screen.getByText('Go to Incidents')).toBeInTheDocument()
  })

  // ── Action shortcuts ─────────────────────────────────────────────────────────

  it('shows "Focus search bar" shortcut', () => {
    renderModal()
    expect(screen.getByText('Focus search bar')).toBeInTheDocument()
  })

  it('shows "Show keyboard shortcuts" shortcut', () => {
    renderModal()
    expect(screen.getByText('Show keyboard shortcuts')).toBeInTheDocument()
  })

  it('shows "Close panel / modal" shortcut', () => {
    renderModal()
    expect(screen.getByText('Close panel / modal')).toBeInTheDocument()
  })

  // ── Key labels ───────────────────────────────────────────────────────────────

  it('renders key labels inside <kbd> elements', () => {
    renderModal()
    const kbds = document.querySelectorAll('kbd')
    expect(kbds.length).toBeGreaterThan(0)
  })

  it('renders "g" key label', () => {
    renderModal()
    const kbds = Array.from(document.querySelectorAll('kbd'))
    expect(kbds.some(k => k.textContent === 'g')).toBe(true)
  })

  it('renders "Esc" key label', () => {
    renderModal()
    const kbds = Array.from(document.querySelectorAll('kbd'))
    expect(kbds.some(k => k.textContent === 'Esc')).toBe(true)
  })

  // ── Close button ─────────────────────────────────────────────────────────────

  it('renders a close button', () => {
    renderModal()
    expect(screen.getByRole('button', { name: 'Close' })).toBeInTheDocument()
  })

  it('clicking close button calls closeShortcutsModal', () => {
    renderModal()
    fireEvent.click(screen.getByRole('button', { name: 'Close' }))
    expect(useUIStore.getState().showShortcutsModal).toBe(false)
  })

  // ── Backdrop click ───────────────────────────────────────────────────────────

  it('clicking the backdrop calls closeShortcutsModal', () => {
    renderModal()
    // The backdrop is the aria-hidden overlay div
    const backdrop = document.querySelector('[aria-hidden="true"]') as HTMLElement
    expect(backdrop).toBeTruthy()
    fireEvent.click(backdrop)
    expect(useUIStore.getState().showShortcutsModal).toBe(false)
  })

  // ── Escape key ───────────────────────────────────────────────────────────────

  it('pressing Escape closes the modal', () => {
    renderModal()
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(useUIStore.getState().showShortcutsModal).toBe(false)
  })

  // ── Accessibility ────────────────────────────────────────────────────────────

  it('dialog has aria-modal="true"', () => {
    renderModal()
    expect(screen.getByRole('dialog')).toHaveAttribute('aria-modal', 'true')
  })
})
