import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, beforeEach, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'

// vi.mock is hoisted before imports
vi.mock('../../stores/authStore', () => ({
  useAuthStore: vi.fn(),
}))

vi.mock('react-router-dom', async (importOriginal) => ({
  ...(await importOriginal<typeof import('react-router-dom')>()),
  useNavigate: vi.fn(),
}))

import { LoginPage } from '../../components/features/auth/LoginPage'
import { useAuthStore } from '../../stores/authStore'
import { useNavigate } from 'react-router-dom'
import { KYRA_MDR_URL, MXTAC_REPO_URL } from '../../lib/links'

const mockUseAuthStore = useAuthStore as unknown as ReturnType<typeof vi.fn>
const mockUseNavigate = useNavigate as unknown as ReturnType<typeof vi.fn>

function makeStore(overrides: Record<string, unknown> = {}) {
  return {
    login: vi.fn(),
    submitMfa: vi.fn(),
    cancelMfa: vi.fn(),
    submitNewPassword: vi.fn(),
    cancelPasswordChange: vi.fn(),
    isLoading: false,
    error: null,
    isAuthenticated: false,
    mfaPending: false,
    passwordChangePending: false,
    clearError: vi.fn(),
    ...overrides,
  }
}

function renderLoginPage(overrides: Record<string, unknown> = {}, from?: { pathname: string; search?: string }) {
  const store = makeStore(overrides)
  mockUseAuthStore.mockReturnValue(store)
  render(
    <MemoryRouter initialEntries={[{ pathname: '/login', state: from ? { from } : undefined }]}>
      <LoginPage />
    </MemoryRouter>,
  )
  return store
}

const type = (label: string, value: string) =>
  fireEvent.change(screen.getByLabelText(label), { target: { value } })

describe('LoginPage after sign-in', () => {
  it('returns to the page that was asked for while signed out', () => {
    const navigate = vi.fn()
    mockUseNavigate.mockReturnValue(navigate)
    renderLoginPage({ isAuthenticated: true }, { pathname: '/rules', search: '?level=high' })
    expect(navigate).toHaveBeenCalledWith('/rules?level=high', { replace: true })
  })

  it('opens Overview when no page was asked for, or the page was the login page', () => {
    const navigate = vi.fn()
    mockUseNavigate.mockReturnValue(navigate)
    renderLoginPage({ isAuthenticated: true }, { pathname: '/login' })
    expect(navigate).toHaveBeenCalledWith('/', { replace: true })
  })
})

describe('LoginPage', () => {
  let navigate: ReturnType<typeof vi.fn>

  beforeEach(() => {
    navigate = vi.fn()
    mockUseNavigate.mockReturnValue(navigate)
  })

  describe('sign-in form', () => {
    it('shows the product name, heading and tagline', () => {
      renderLoginPage()
      expect(screen.getByText('MxTac')).toBeInTheDocument()
      expect(screen.getByRole('heading', { name: 'Sign in' })).toBeInTheDocument()
      expect(screen.getByText('Open-source ATT&CK detection platform')).toBeInTheDocument()
    })

    it('has required email and password fields that password managers can fill', () => {
      renderLoginPage()
      const email = screen.getByLabelText('Email')
      expect(email).toHaveAttribute('type', 'email')
      expect(email).toHaveAttribute('autocomplete', 'email')
      expect(email).toBeRequired()
      const password = screen.getByLabelText('Password')
      expect(password).toHaveAttribute('type', 'password')
      expect(password).toHaveAttribute('autocomplete', 'current-password')
      expect(password).toBeRequired()
    })

    it('submits the typed email and password', () => {
      const store = renderLoginPage()
      type('Email', 'analyst@mxtac.local')
      type('Password', 'Analyst-Passw0rd')
      fireEvent.click(screen.getByRole('button', { name: 'Sign in' }))
      expect(store.login).toHaveBeenCalledTimes(1)
      expect(store.login).toHaveBeenCalledWith('analyst@mxtac.local', 'Analyst-Passw0rd')
    })

    it('disables the submit button and shows progress while signing in', () => {
      renderLoginPage({ isLoading: true })
      expect(screen.getByRole('button', { name: 'Signing in…' })).toBeDisabled()
    })

    it('shows the error as an alert', () => {
      renderLoginPage({ error: 'Invalid credentials' })
      expect(screen.getByRole('alert')).toHaveTextContent('Invalid credentials')
    })

    it('shows no alert when there is no error', () => {
      renderLoginPage()
      expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    })

    it.each(['Email', 'Password'])('clears the error when the %s field is edited', (label) => {
      const store = renderLoginPage({ error: 'Invalid credentials' })
      type(label, 'x')
      expect(store.clearError).toHaveBeenCalledTimes(1)
    })

    it('does not call clearError while there is no error', () => {
      const store = renderLoginPage()
      type('Email', 'x')
      expect(store.clearError).not.toHaveBeenCalled()
    })
  })

  describe('redirect', () => {
    it('goes to the overview when already authenticated', () => {
      renderLoginPage({ isAuthenticated: true })
      expect(navigate).toHaveBeenCalledWith('/', { replace: true })
    })

    it('stays on the page when not authenticated', () => {
      renderLoginPage()
      expect(navigate).not.toHaveBeenCalled()
    })
  })

  describe('two-factor step', () => {
    it('replaces the sign-in form with the code prompt', () => {
      renderLoginPage({ mfaPending: true })
      expect(screen.getByRole('heading', { name: 'Two-factor authentication' })).toBeInTheDocument()
      expect(screen.getByText('Enter the 6-digit code from your authenticator app.')).toBeInTheDocument()
      expect(screen.getByLabelText('Authentication code')).toHaveAttribute('autocomplete', 'one-time-code')
      expect(screen.queryByLabelText('Email')).not.toBeInTheDocument()
      expect(screen.queryByLabelText('Password')).not.toBeInTheDocument()
    })

    it('submits as soon as six digits are typed', () => {
      const store = renderLoginPage({ mfaPending: true })
      type('Authentication code', '12345')
      expect(store.submitMfa).not.toHaveBeenCalled()
      type('Authentication code', '123456')
      expect(store.submitMfa).toHaveBeenCalledTimes(1)
      expect(store.submitMfa).toHaveBeenCalledWith('123456')
    })

    it('submits the code with the Verify button', () => {
      const store = renderLoginPage({ mfaPending: true })
      type('Authentication code', '1234')
      fireEvent.click(screen.getByRole('button', { name: 'Verify' }))
      expect(store.submitMfa).toHaveBeenCalledWith('1234')
    })

    it('disables the Verify button and shows progress while verifying', () => {
      renderLoginPage({ mfaPending: true, isLoading: true })
      expect(screen.getByRole('button', { name: 'Verifying…' })).toBeDisabled()
    })

    it('shows the error as an alert and clears it when the code is edited', () => {
      const store = renderLoginPage({ mfaPending: true, error: 'Invalid code' })
      expect(screen.getByRole('alert')).toHaveTextContent('Invalid code')
      type('Authentication code', '1')
      expect(store.clearError).toHaveBeenCalledTimes(1)
    })

    it('switches to a backup code, which is submitted only with the button', () => {
      const store = renderLoginPage({ mfaPending: true })
      type('Authentication code', '123')
      fireEvent.click(screen.getByRole('button', { name: 'Use a backup code' }))

      const input = screen.getByLabelText('Backup code')
      expect(input).toHaveValue('')
      expect(input).toHaveAttribute('maxlength', '8')
      expect(screen.getByText('Enter one of your backup codes.')).toBeInTheDocument()

      type('Backup code', 'ABCDEF')
      expect(store.submitMfa).not.toHaveBeenCalled()
      type('Backup code', 'ABCDEFGH')
      fireEvent.click(screen.getByRole('button', { name: 'Verify' }))
      expect(store.submitMfa).toHaveBeenCalledTimes(1)
      expect(store.submitMfa).toHaveBeenCalledWith('ABCDEFGH')
    })

    it('switches back from a backup code to the authenticator app', () => {
      renderLoginPage({ mfaPending: true })
      fireEvent.click(screen.getByRole('button', { name: 'Use a backup code' }))
      fireEvent.click(screen.getByRole('button', { name: 'Use authenticator app instead' }))
      expect(screen.getByLabelText('Authentication code')).toHaveAttribute('maxlength', '6')
    })

    it('cancels the two-factor step with "Back to sign in"', () => {
      const store = renderLoginPage({ mfaPending: true })
      fireEvent.click(screen.getByRole('button', { name: 'Back to sign in' }))
      expect(store.cancelMfa).toHaveBeenCalledTimes(1)
    })
  })

  describe('set a new password step', () => {
    const NEW = 'Brand-New-Passw0rd'

    function fill(newPassword: string, confirm = newPassword) {
      type('New password', newPassword)
      type('Confirm new password', confirm)
    }
    const submit = () => fireEvent.click(screen.getByRole('button', { name: 'Set password and sign in' }))

    it('replaces the sign-in form when the login asks for a password change', () => {
      renderLoginPage({ passwordChangePending: true })
      expect(screen.getByRole('heading', { name: 'Set a new password' })).toBeInTheDocument()
      expect(screen.queryByLabelText('Email')).not.toBeInTheDocument()
      expect(screen.queryByLabelText('Password')).not.toBeInTheDocument()
      for (const label of ['New password', 'Confirm new password']) {
        const input = screen.getByLabelText(label)
        expect(input).toHaveAttribute('type', 'password')
        expect(input).toHaveAttribute('autocomplete', 'new-password')
      }
    })

    it('states the password policy in one line', () => {
      renderLoginPage({ passwordChangePending: true })
      expect(screen.getByText('At least 8 characters with 3 of: uppercase, lowercase, digits, symbols.')).toBeInTheDocument()
    })

    it('takes priority over the two-factor step', () => {
      renderLoginPage({ passwordChangePending: true, mfaPending: true })
      expect(screen.getByRole('heading', { name: 'Set a new password' })).toBeInTheDocument()
      expect(screen.queryByLabelText('Authentication code')).not.toBeInTheDocument()
    })

    it('submits the new password', () => {
      const store = renderLoginPage({ passwordChangePending: true })
      fill(NEW)
      submit()
      expect(store.submitNewPassword).toHaveBeenCalledTimes(1)
      expect(store.submitNewPassword).toHaveBeenCalledWith(NEW)
    })

    it('does not send when the two passwords differ', () => {
      const store = renderLoginPage({ passwordChangePending: true })
      fill(NEW, 'Another-Passw0rd')
      submit()
      expect(screen.getByRole('alert')).toHaveTextContent('The passwords do not match')
      expect(store.submitNewPassword).not.toHaveBeenCalled()
    })

    it.each([
      ['Ab1!', 'at least 8 characters'],
      ['alllowercase', 'Use at least 3 of'],
      ['Abcd1111efgh', 'more than 3 times in a row'],
    ])('does not send "%s", which breaks the policy', (weak, message) => {
      const store = renderLoginPage({ passwordChangePending: true })
      fill(weak)
      submit()
      expect(screen.getByRole('alert')).toHaveTextContent(message)
      expect(store.submitNewPassword).not.toHaveBeenCalled()
    })

    it('clears the browser-side problem when a field is edited', () => {
      renderLoginPage({ passwordChangePending: true })
      fill('short')
      submit()
      expect(screen.getByRole('alert')).toBeInTheDocument()
      type('New password', NEW)
      expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    })

    it('shows the validation error of the server and clears it when a field is edited', () => {
      const store = renderLoginPage({ passwordChangePending: true, error: 'Cannot reuse one of your last 2 passwords' })
      expect(screen.getByRole('alert')).toHaveTextContent('Cannot reuse one of your last 2 passwords')
      type('New password', 'x')
      expect(store.clearError).toHaveBeenCalledTimes(1)
    })

    it('disables the button and shows progress while saving', () => {
      renderLoginPage({ passwordChangePending: true, isLoading: true })
      expect(screen.getByRole('button', { name: 'Saving…' })).toBeDisabled()
    })

    it('cancels with "Back to sign in"', () => {
      const store = renderLoginPage({ passwordChangePending: true })
      fireEvent.click(screen.getByRole('button', { name: 'Back to sign in' }))
      expect(store.cancelPasswordChange).toHaveBeenCalledTimes(1)
      expect(store.submitNewPassword).not.toHaveBeenCalled()
    })

    it('continues with the two-factor step when the server asks for it afterwards', () => {
      mockUseAuthStore.mockReturnValue(makeStore({ passwordChangePending: true }))
      const view = render(<MemoryRouter><LoginPage /></MemoryRouter>)
      fill(NEW)

      mockUseAuthStore.mockReturnValue(makeStore({ mfaPending: true }))
      view.rerender(<MemoryRouter><LoginPage /></MemoryRouter>)

      expect(screen.getByRole('heading', { name: 'Two-factor authentication' })).toBeInTheDocument()
      expect(screen.queryByLabelText('New password')).not.toBeInTheDocument()
    })

    it('forgets the typed passwords when the step ends', () => {
      mockUseAuthStore.mockReturnValue(makeStore({ passwordChangePending: true }))
      const view = render(<MemoryRouter><LoginPage /></MemoryRouter>)
      fill(NEW)

      mockUseAuthStore.mockReturnValue(makeStore())
      view.rerender(<MemoryRouter><LoginPage /></MemoryRouter>)
      expect(screen.getByRole('heading', { name: 'Sign in' })).toBeInTheDocument()

      mockUseAuthStore.mockReturnValue(makeStore({ passwordChangePending: true }))
      view.rerender(<MemoryRouter><LoginPage /></MemoryRouter>)
      expect(screen.getByLabelText('New password')).toHaveValue('')
      expect(screen.getByLabelText('Confirm new password')).toHaveValue('')
    })

    it('goes to the overview once the new password signed the user in', () => {
      renderLoginPage({ isAuthenticated: true })
      expect(navigate).toHaveBeenCalledWith('/', { replace: true })
    })
  })

  describe('footer links', () => {
    it.each([
      ['Source on GitHub', MXTAC_REPO_URL],
      ['Managed 24/7 monitoring: KYRA MDR', KYRA_MDR_URL],
    ])('"%s" opens in a new tab without leaking the opener', (name, href) => {
      renderLoginPage()
      const link = screen.getByRole('link', { name })
      expect(link).toHaveAttribute('href', href)
      expect(link).toHaveAttribute('target', '_blank')
      expect(link.getAttribute('rel')).toContain('noopener')
    })

    it('stay visible during the two-factor step', () => {
      renderLoginPage({ mfaPending: true })
      expect(screen.getByRole('link', { name: /KYRA MDR/ })).toHaveAttribute('href', KYRA_MDR_URL)
    })
  })
})
