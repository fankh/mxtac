import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it } from 'vitest'
import { KeyboardShortcutsModal } from '../../components/shared/KeyboardShortcutsModal'
import { useUIStore } from '../../stores/uiStore'

function setup() {
  const user = userEvent.setup()
  render(<KeyboardShortcutsModal />)
  return { user, dialog: screen.getByRole('dialog', { name: 'Keyboard Shortcuts' }) }
}

/** Key labels shown next to a shortcut description, in order. */
function keysFor(description: string): string[] {
  const definition = screen.getByText(description).nextElementSibling
  if (!(definition instanceof HTMLElement)) throw new Error(`No keys listed for "${description}"`)
  return within(definition).getAllByText(/\S/, { selector: 'kbd' }).map((key) => key.textContent ?? '')
}

/** The dimmed layer behind the dialog, which is what a click outside lands on. */
function backdropOf(dialog: HTMLElement): Element {
  const backdrop = dialog.previousElementSibling
  if (!backdrop) throw new Error('The dialog has no backdrop')
  return backdrop
}

function isOpen() {
  return useUIStore.getState().showShortcutsModal
}

describe('KeyboardShortcutsModal', () => {
  beforeEach(() => {
    useUIStore.setState({ showShortcutsModal: true })
  })

  it('is a dialog named by its title, with a description', () => {
    const { dialog } = setup()
    expect(screen.getByRole('heading', { name: 'Keyboard Shortcuts' })).toBeInTheDocument()
    expect(dialog).toHaveAccessibleDescription('Keys for moving between pages and for common actions.')
  })

  it('groups the shortcuts under Navigation and Actions', () => {
    setup()
    const navigation = screen.getByRole('region', { name: 'Navigation' })
    const actions = screen.getByRole('region', { name: 'Actions' })

    expect(within(navigation).getAllByRole('term').map((term) => term.textContent)).toEqual([
      'Go to Overview',
      'Go to Detections',
      'Go to Rules',
      'Go to Hunt',
      'Go to ATT&CK coverage',
      'Go to Sources',
      'Go to Incidents',
    ])
    expect(within(actions).getAllByRole('term').map((term) => term.textContent)).toEqual([
      'Focus search bar',
      'Show keyboard shortcuts',
      'Close panel / modal',
    ])
  })

  it.each([
    ['Go to Overview', ['g', 'd']],
    ['Go to Detections', ['g', 'e']],
    ['Go to Rules', ['g', 'r']],
    ['Go to Hunt', ['g', 'h']],
    ['Go to ATT&CK coverage', ['g', 'c']],
    ['Go to Sources', ['g', 's']],
    ['Go to Incidents', ['g', 'i']],
    ['Focus search bar', ['/']],
    ['Show keyboard shortcuts', ['?']],
    ['Close panel / modal', ['Esc']],
  ])('lists the keys for "%s"', (description, keys) => {
    setup()
    expect(keysFor(description)).toEqual(keys)
  })

  it('reads two-key shortcuts as a sequence', () => {
    setup()
    expect(screen.getByText('Go to Overview').nextElementSibling).toHaveTextContent('gthend')
  })

  it('closes from the close button', async () => {
    const { user } = setup()
    await user.click(screen.getByRole('button', { name: 'Close' }))
    expect(isOpen()).toBe(false)
  })

  it('closes on Escape', async () => {
    const { user } = setup()
    await user.keyboard('{Escape}')
    expect(isOpen()).toBe(false)
  })

  it('closes on a click outside the dialog', async () => {
    const { user, dialog } = setup()
    await user.click(backdropOf(dialog))
    expect(isOpen()).toBe(false)
  })

  it('stays open on a click inside the dialog', async () => {
    const { user } = setup()
    await user.click(screen.getByText('Go to Rules'))
    expect(isOpen()).toBe(true)
  })

  it('keeps keyboard focus inside the dialog', async () => {
    const { user, dialog } = setup()
    for (let i = 0; i < 3; i++) {
      await user.tab()
      expect(dialog).toContainElement(document.activeElement as HTMLElement)
    }
  })
})
