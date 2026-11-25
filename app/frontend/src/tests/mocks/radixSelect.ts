import { fireEvent, screen, within } from '@testing-library/react'

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
