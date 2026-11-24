import { fireEvent, screen, within } from '@testing-library/react'

class ResizeObserverStub implements ResizeObserver {
  constructor(_callback: ResizeObserverCallback) {}
  observe() {}
  unobserve() {}
  disconnect() {}
}

/**
 * jsdom lacks a few browser APIs that the Radix Select primitive calls.
 * Call once at the top of a test file that opens a Select.
 */
export function installRadixSelectPolyfills() {
  if (typeof window.ResizeObserver === 'undefined') window.ResizeObserver = ResizeObserverStub
  if (!Element.prototype.scrollIntoView) Element.prototype.scrollIntoView = () => {}
  if (!Element.prototype.hasPointerCapture) Element.prototype.hasPointerCapture = () => false
  if (!Element.prototype.releasePointerCapture) Element.prototype.releasePointerCapture = () => {}
}

/** Opens the Select with the given accessible name and returns its option labels. */
export async function openSelect(name: string | RegExp): Promise<string[]> {
  fireEvent.keyDown(screen.getByRole('combobox', { name }), { key: 'Enter' })
  const listbox = await screen.findByRole('listbox')
  return within(listbox)
    .getAllByRole('option')
    .map((option) => option.textContent ?? '')
}

/** Opens the Select with the given accessible name and picks one option. */
export async function chooseOption(name: string | RegExp, option: string | RegExp) {
  fireEvent.keyDown(screen.getByRole('combobox', { name }), { key: 'Enter' })
  const listbox = await screen.findByRole('listbox')
  fireEvent.keyDown(within(listbox).getByRole('option', { name: option }), { key: 'Enter' })
}
