// vi.mock is hoisted before imports — declare all module mocks first.

vi.mock('../../lib/api', async (importOriginal) => {
  const actual = await importOriginal<typeof ApiModule>()
  return {
    ...actual,
    authApi: { ...actual.authApi, me: vi.fn(), mfaDisable: vi.fn(), changePassword: vi.fn() },
    usersApi: {
      list: vi.fn(),
      create: vi.fn(),
      update: vi.fn(),
      delete: vi.fn(),
    },
  }
})

// The real TopBar opens the alert WebSocket; the page frame only needs its slots.
vi.mock('../../components/layout/TopBar', () => ({
  TopBar: ({ crumb, actions }: { crumb: string; actions?: ReactNode }) => (
    <header>
      <h1>{crumb}</h1>
      {actions}
    </header>
  ),
}))

// The MFA flow has its own test file.
vi.mock('../../components/features/auth/MfaSetupModal', () => ({
  MfaSetupModal: ({ onClose }: { onClose: () => void }) => (
    <div data-testid="mfa-modal">
      <button onClick={onClose}>Close MFA</button>
    </div>
  ),
}))

import type { ReactNode } from 'react'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { SettingsPage } from '../../components/features/settings/SettingsPage'
import type * as ApiModule from '../../lib/api'
import { authApi, usersApi } from '../../lib/api'
import { useAuthStore } from '../../stores/authStore'
import { useUIStore } from '../../stores/uiStore'
import type { User } from '../../types/api'
import { chooseOption, installRadixSelectPolyfills } from '../mocks/radixSelect'

installRadixSelectPolyfills()

const meMock = vi.mocked(authApi.me)
const mfaDisableMock = vi.mocked(authApi.mfaDisable)
const changePasswordMock = vi.mocked(authApi.changePassword)
const api = vi.mocked(usersApi)

const ADMIN: User = {
  id: '5b0c7c0e-6f0b-4f65-9a54-2c3b1d0e8a11', email: 'admin@mxtac.local', full_name: 'Ada Admin', role: 'admin',
  is_active: true, mfa_enabled: false, must_change_password: false,
}
const ANALYST: User = {
  id: 'd2a9f3b4-18c7-4e2a-b6d1-7f40c9e5a3c2', email: 'analyst@mxtac.local', full_name: null, role: 'analyst',
  is_active: true, mfa_enabled: true, must_change_password: false,
}
const FORMER: User = {
  id: '9e4b1a6d-3c52-4f0e-8d7a-1b6c2f9a4e30', email: 'former@mxtac.local', full_name: 'Former Hunter', role: 'hunter',
  is_active: false, mfa_enabled: false, must_change_password: true,
}

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <SettingsPage />
    </QueryClientProvider>,
  )
}

function signInAs(role: string, email = 'admin@mxtac.local') {
  useAuthStore.setState({ user: { email, role } })
}

async function openUsers() {
  renderPage()
  fireEvent.click(screen.getByRole('tab', { name: 'Users' }))
  await screen.findByText('analyst@mxtac.local')
}

function rowOf(text: string): HTMLElement {
  return screen.getByText(text).closest('tr') as HTMLElement
}

function notifications() {
  return useUIStore.getState().notifications
}

beforeEach(() => {
  vi.clearAllMocks()
  useUIStore.setState({ notifications: [], theme: 'dark' })
  signInAs('admin')
  meMock.mockResolvedValue({ email: 'admin@mxtac.local', role: 'admin', full_name: 'Ada Admin', mfa_enabled: false })
  api.list.mockResolvedValue([ADMIN, ANALYST, FORMER])
})

describe('SettingsPage', () => {
  describe('tabs', () => {
    it('shows only the tabs for features the backend has', () => {
      renderPage()
      expect(screen.getAllByRole('tab').map((t) => t.textContent)).toEqual(['Profile and security', 'Users', 'Appearance'])
    })

    it('hides the Users tab from roles other than admin', () => {
      signInAs('engineer', 'eng@mxtac.local')
      renderPage()
      expect(screen.queryByRole('tab', { name: 'Users' })).not.toBeInTheDocument()
      expect(api.list).not.toHaveBeenCalled()
    })
  })

  describe('profile and security', () => {
    it('shows the current user from GET /auth/me', async () => {
      renderPage()
      expect(await screen.findByText('Ada Admin')).toBeInTheDocument()
      expect(screen.getByText('admin@mxtac.local')).toBeInTheDocument()
      expect(screen.getByText('Off')).toBeInTheDocument()
    })

    it('opens the MFA setup from the security card', async () => {
      renderPage()
      fireEvent.click(await screen.findByRole('button', { name: 'Set up MFA' }))
      expect(screen.getByTestId('mfa-modal')).toBeInTheDocument()
      fireEvent.click(screen.getByRole('button', { name: 'Close MFA' }))
      expect(screen.queryByTestId('mfa-modal')).not.toBeInTheDocument()
    })

    it('shows MFA as on when it is enabled', async () => {
      meMock.mockResolvedValue({ email: 'admin@mxtac.local', role: 'admin', full_name: null, mfa_enabled: true })
      renderPage()
      expect(await screen.findByRole('button', { name: 'View MFA status' })).toBeInTheDocument()
      expect(screen.getByText('On')).toBeInTheDocument()
    })

    it('offers Retry when the profile cannot be loaded', async () => {
      meMock.mockRejectedValueOnce(new Error('boom'))
      renderPage()
      expect(await screen.findByText('Could not load your profile.')).toBeInTheDocument()
      fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
      expect(await screen.findByText('Ada Admin')).toBeInTheDocument()
    })
  })

  describe('change password', () => {
    const CURRENT = 'Current-Passw0rd'
    const NEW = 'Brand-New-Passw0rd'

    async function openForm() {
      renderPage()
      return within(await screen.findByRole('form', { name: 'Change password' }))
    }

    function fill(form: ReturnType<typeof within>, current: string, next: string, confirm = next) {
      fireEvent.change(form.getByLabelText('Current password'), { target: { value: current } })
      fireEvent.change(form.getByLabelText('New password'), { target: { value: next } })
      fireEvent.change(form.getByLabelText('Confirm new password'), { target: { value: confirm } })
    }

    const submit = (form: ReturnType<typeof within>) =>
      fireEvent.click(form.getByRole('button', { name: 'Change password' }))

    it('replaces the old "not available" notice with a form', async () => {
      const form = await openForm()
      expect(screen.queryByText(/not available/)).not.toBeInTheDocument()
      expect(form.getByLabelText('Current password')).toHaveAttribute('autocomplete', 'current-password')
      expect(form.getByLabelText('New password')).toHaveAttribute('autocomplete', 'new-password')
      expect(form.getByText(/At least 8 characters with 3 of/)).toBeInTheDocument()
    })

    it('changes the password through POST /auth/password, confirms and resets the form', async () => {
      changePasswordMock.mockResolvedValue(undefined)
      const form = await openForm()
      fill(form, CURRENT, NEW)
      submit(form)

      await waitFor(() => expect(changePasswordMock).toHaveBeenCalledWith(CURRENT, NEW))
      await waitFor(() => expect(notifications()[0]).toMatchObject({ type: 'success', title: 'Password changed' }))
      expect(form.getByLabelText('Current password')).toHaveValue('')
      expect(form.getByLabelText('New password')).toHaveValue('')
      expect(form.getByLabelText('Confirm new password')).toHaveValue('')
      expect(form.queryByRole('alert')).not.toBeInTheDocument()
    })

    it('shows the server message when the current password is wrong and keeps the form', async () => {
      changePasswordMock.mockRejectedValue({ response: { data: { detail: 'Current password is incorrect' } } })
      const form = await openForm()
      fill(form, 'Wrong-Passw0rd', NEW)
      submit(form)

      expect(await form.findByRole('alert')).toHaveTextContent('Current password is incorrect')
      expect(notifications()[0]).toMatchObject({
        type: 'error', title: 'Password change failed', message: 'Current password is incorrect',
      })
      expect(form.getByLabelText('New password')).toHaveValue(NEW)
    })

    it('shows the history rule of the server', async () => {
      changePasswordMock.mockRejectedValue({ response: { data: { detail: 'Cannot reuse one of your last 2 passwords' } } })
      const form = await openForm()
      fill(form, CURRENT, NEW)
      submit(form)
      expect(await form.findByRole('alert')).toHaveTextContent('Cannot reuse one of your last 2 passwords')
    })

    it('checks the form before sending', async () => {
      const form = await openForm()
      submit(form)
      expect(form.getByRole('alert')).toHaveTextContent('Enter your current password')

      fill(form, CURRENT, 'short')
      submit(form)
      expect(form.getByRole('alert')).toHaveTextContent('at least 8 characters')

      fill(form, CURRENT, 'alllowercase')
      submit(form)
      expect(form.getByRole('alert')).toHaveTextContent('Use at least 3 of')

      fill(form, CURRENT, NEW, 'Another-Passw0rd')
      submit(form)
      expect(form.getByRole('alert')).toHaveTextContent('The new passwords do not match')

      fill(form, CURRENT, CURRENT)
      submit(form)
      expect(form.getByRole('alert')).toHaveTextContent('must differ from the current one')

      expect(changePasswordMock).not.toHaveBeenCalled()
    })

    it('clears the error when a field is edited', async () => {
      const form = await openForm()
      submit(form)
      expect(form.getByRole('alert')).toBeInTheDocument()
      fireEvent.change(form.getByLabelText('Current password'), { target: { value: 'x' } })
      expect(form.queryByRole('alert')).not.toBeInTheDocument()
    })

    it('disables the button while the request is running', async () => {
      changePasswordMock.mockReturnValue(new Promise(() => {}))
      const form = await openForm()
      fill(form, CURRENT, NEW)
      submit(form)
      expect(await form.findByRole('button', { name: 'Changing…' })).toBeDisabled()
    })
  })

  describe('users', () => {
    it('lists users with role, status and MFA state', async () => {
      await openUsers()
      const admin = rowOf('Ada Admin')
      expect(within(admin).getByText('(you)')).toBeInTheDocument()
      expect(within(admin).getByText('Active')).toBeInTheDocument()
      const former = rowOf('Former Hunter')
      expect(within(former).getByText('Inactive')).toBeInTheDocument()
      expect(within(former).getByText('hunter')).toBeInTheDocument()
    })

    it('offers Retry when users cannot be loaded', async () => {
      api.list.mockRejectedValueOnce(new Error('boom'))
      renderPage()
      fireEvent.click(screen.getByRole('tab', { name: 'Users' }))
      expect(await screen.findByText('Could not load users.')).toBeInTheDocument()
      fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
      expect(await screen.findByText('analyst@mxtac.local')).toBeInTheDocument()
    })

    it('filters users by search text', async () => {
      await openUsers()
      fireEvent.change(screen.getByLabelText('Search users'), { target: { value: 'former' } })
      expect(screen.queryByText('analyst@mxtac.local')).not.toBeInTheDocument()
      expect(screen.getByText('Former Hunter')).toBeInTheDocument()
    })

    it('does not let an admin deactivate their own account', async () => {
      await openUsers()
      expect(screen.getByTitle('You cannot deactivate your own account')).toBeDisabled()
    })

    it('deactivates a user after confirmation', async () => {
      api.delete.mockResolvedValue(undefined)
      await openUsers()
      fireEvent.click(screen.getByTitle('Deactivate analyst@mxtac.local'))
      const dialog = await screen.findByRole('dialog')
      fireEvent.click(within(dialog).getByRole('button', { name: 'Deactivate' }))
      await waitFor(() => expect(api.delete).toHaveBeenCalledWith(ANALYST.id))
    })

    it('reactivates an inactive user', async () => {
      api.update.mockResolvedValue({ ...FORMER, is_active: true })
      await openUsers()
      fireEvent.click(screen.getByTitle('Reactivate former@mxtac.local'))
      await waitFor(() => expect(api.update).toHaveBeenCalledWith(FORMER.id, { is_active: true }))
    })

    it('resets MFA for a user through POST /auth/mfa/disable', async () => {
      mfaDisableMock.mockResolvedValue({ message: 'MFA disabled' })
      await openUsers()
      expect(screen.queryByTitle('Reset MFA for admin@mxtac.local')).not.toBeInTheDocument()
      fireEvent.click(screen.getByTitle('Reset MFA for analyst@mxtac.local'))
      const dialog = await screen.findByRole('dialog')
      fireEvent.click(within(dialog).getByRole('button', { name: 'Reset MFA' }))
      await waitFor(() => expect(mfaDisableMock).toHaveBeenCalledWith(ANALYST.id))
    })

    it('adds a user with a temporary password', async () => {
      api.create.mockResolvedValue({ ...ANALYST, id: '0c1f6d0a-5c0e-4b7e-9f4e-6a1d7b3c2e55', email: 'new@mxtac.local' })
      await openUsers()
      fireEvent.click(screen.getByRole('button', { name: 'Add user' }))
      const dialog = await screen.findByRole('dialog')
      fireEvent.change(within(dialog).getByLabelText('Email'), { target: { value: 'new@mxtac.local' } })
      fireEvent.change(within(dialog).getByLabelText('Full name'), { target: { value: 'New Person' } })
      fireEvent.change(within(dialog).getByLabelText('Temporary password'), { target: { value: 'Welcome-2026' } })
      await chooseOption('Role', 'Hunter')
      fireEvent.click(within(dialog).getByRole('button', { name: 'Add user' }))
      await waitFor(() => expect(api.create).toHaveBeenCalledWith({
        email: 'new@mxtac.local', full_name: 'New Person', role: 'hunter', password: 'Welcome-2026',
      }))
    })

    it('says that the temporary password must be changed at first sign-in', async () => {
      await openUsers()
      fireEvent.click(screen.getByRole('button', { name: 'Add user' }))
      const dialog = await screen.findByRole('dialog')
      expect(within(dialog).getByText(/They must change it at first sign-in/)).toBeInTheDocument()
      expect(within(dialog).getByLabelText('Temporary password')).toHaveAttribute('type', 'password')
    })

    it('has no invite action', async () => {
      await openUsers()
      expect(screen.queryByRole('button', { name: /invite/i })).not.toBeInTheDocument()
      expect(screen.queryByText(/invite/i)).not.toBeInTheDocument()
    })

    it('checks the email and the password policy before sending', async () => {
      await openUsers()
      fireEvent.click(screen.getByRole('button', { name: 'Add user' }))
      const dialog = await screen.findByRole('dialog')
      const submit = within(dialog).getByRole('button', { name: 'Add user' })
      fireEvent.change(within(dialog).getByLabelText('Email'), { target: { value: 'not-an-email' } })
      fireEvent.click(submit)
      expect(within(dialog).getByRole('alert')).toHaveTextContent('Enter a valid email address')

      fireEvent.change(within(dialog).getByLabelText('Email'), { target: { value: 'new@mxtac.local' } })
      fireEvent.change(within(dialog).getByLabelText('Temporary password'), { target: { value: 'short' } })
      fireEvent.click(submit)
      expect(within(dialog).getByRole('alert')).toHaveTextContent('at least 8 characters')

      fireEvent.change(within(dialog).getByLabelText('Temporary password'), { target: { value: 'alllowercase' } })
      fireEvent.click(submit)
      expect(within(dialog).getByRole('alert')).toHaveTextContent('Use at least 3 of')
      expect(api.create).not.toHaveBeenCalled()
    })

    it('shows the server message when adding a user fails', async () => {
      api.create.mockRejectedValue({ response: { data: { detail: 'Email already registered' } } })
      await openUsers()
      fireEvent.click(screen.getByRole('button', { name: 'Add user' }))
      const dialog = await screen.findByRole('dialog')
      fireEvent.change(within(dialog).getByLabelText('Email'), { target: { value: 'analyst@mxtac.local' } })
      fireEvent.change(within(dialog).getByLabelText('Temporary password'), { target: { value: 'Welcome-2026' } })
      fireEvent.click(within(dialog).getByRole('button', { name: 'Add user' }))
      expect(await within(dialog).findByText('Email already registered')).toBeInTheDocument()
      expect(notifications()[0]).toMatchObject({ type: 'error', title: 'Add user failed' })
    })

    it('changes a role through PATCH /users/{id}', async () => {
      api.update.mockResolvedValue({ ...ANALYST, role: 'engineer' })
      await openUsers()
      fireEvent.click(screen.getByTitle('Edit analyst@mxtac.local'))
      const dialog = await screen.findByRole('dialog')
      await chooseOption('Role', 'Engineer')
      fireEvent.click(within(dialog).getByRole('button', { name: 'Save changes' }))
      await waitFor(() => expect(api.update).toHaveBeenCalledWith(ANALYST.id, { role: 'engineer' }))
    })

    it('does not let an admin change their own role', async () => {
      await openUsers()
      fireEvent.click(screen.getByTitle('Edit admin@mxtac.local'))
      const dialog = await screen.findByRole('dialog')
      expect(within(dialog).getByRole('combobox', { name: 'Role' })).toBeDisabled()
      expect(within(dialog).getByText('You cannot change your own role.')).toBeInTheDocument()
    })
  })

  describe('appearance', () => {
    it('switches between the light and dark themes', () => {
      renderPage()
      fireEvent.click(screen.getByRole('tab', { name: 'Appearance' }))
      expect(screen.getByRole('button', { name: /Dark/ })).toHaveAttribute('aria-pressed', 'true')
      fireEvent.click(screen.getByRole('button', { name: /Light/ }))
      expect(useUIStore.getState().theme).toBe('light')
      expect(document.documentElement.classList.contains('dark')).toBe(false)
      expect(screen.getByRole('button', { name: /Light/ })).toHaveAttribute('aria-pressed', 'true')

      fireEvent.click(screen.getByRole('button', { name: /Dark/ }))
      expect(useUIStore.getState().theme).toBe('dark')
      expect(document.documentElement.classList.contains('dark')).toBe(true)
    })
  })
})
