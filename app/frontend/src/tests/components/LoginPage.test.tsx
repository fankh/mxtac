import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { describe, it, expect, beforeEach, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'

// vi.mock is hoisted — runs before imports
vi.mock('../../stores/authStore', () => ({
  useAuthStore: vi.fn(),
}))

vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>()
  return {
    ...actual,
    useNavigate: vi.fn(),
  }
})

import { LoginPage } from '../../components/features/auth/LoginPage'
import { useAuthStore } from '../../stores/authStore'
import { useNavigate } from 'react-router-dom'

const mockUseAuthStore = useAuthStore as unknown as ReturnType<typeof vi.fn>
const mockUseNavigate  = useNavigate  as unknown as ReturnType<typeof vi.fn>

function makeStore(overrides: Record<string, unknown> = {}) {
  return {
    login: vi.fn(),
    submitMfa: vi.fn(),
    cancelMfa: vi.fn(),
    isLoading: false,
    error: null,
    isAuthenticated: false,
    mfaPending: false,
    clearError: vi.fn(),
    ...overrides,
  }
}

function renderLoginPage() {
  return render(
    <MemoryRouter>
      <LoginPage />
    </MemoryRouter>,
  )
}

describe('LoginPage', () => {
  let mockNavigate: ReturnType<typeof vi.fn>

  beforeEach(() => {
    mockNavigate = vi.fn()
    mockUseNavigate.mockReturnValue(mockNavigate)
    mockUseAuthStore.mockReturnValue(makeStore())
  })

  // ---------------------------------------------------------------------------
  // Branding
  // ---------------------------------------------------------------------------
  describe('Branding', () => {
    it('renders the "M" logo mark', () => {
      renderLoginPage()
      expect(screen.getByText('M')).toBeInTheDocument()
    })

    it('renders the MxTac product name', () => {
      renderLoginPage()
      expect(screen.getByText('MxTac')).toBeInTheDocument()
    })

    it('renders the "Sign in" heading', () => {
      renderLoginPage()
      expect(screen.getByRole('heading', { name: 'Sign in' })).toBeInTheDocument()
    })

    it('renders the platform subtitle', () => {
      renderLoginPage()
      expect(screen.getByText('MITRE ATT&CK Security Platform')).toBeInTheDocument()
    })
  })

  // ---------------------------------------------------------------------------
  // Form fields
  // ---------------------------------------------------------------------------
  describe('Form fields', () => {
    it('renders an email input', () => {
      renderLoginPage()
      expect(screen.getByLabelText('Email')).toBeInTheDocument()
    })

    it('email input has type="email"', () => {
      renderLoginPage()
      expect(screen.getByLabelText('Email')).toHaveAttribute('type', 'email')
    })

    it('email input has autocomplete="email"', () => {
      renderLoginPage()
      expect(screen.getByLabelText('Email')).toHaveAttribute('autocomplete', 'email')
    })

    it('renders a password input', () => {
      renderLoginPage()
      expect(screen.getByLabelText('Password')).toBeInTheDocument()
    })

    it('password input has type="password"', () => {
      renderLoginPage()
      expect(screen.getByLabelText('Password')).toHaveAttribute('type', 'password')
    })

    it('password input has autocomplete="current-password"', () => {
      renderLoginPage()
      expect(screen.getByLabelText('Password')).toHaveAttribute('autocomplete', 'current-password')
    })

    it('renders a submit button labelled "Sign in"', () => {
      renderLoginPage()
      expect(screen.getByRole('button', { name: 'Sign in' })).toBeInTheDocument()
    })
  })

  // ---------------------------------------------------------------------------
  // Loading state
  // ---------------------------------------------------------------------------
  describe('Loading state', () => {
    it('shows "Signing in…" text on the button while isLoading is true', () => {
      mockUseAuthStore.mockReturnValue(makeStore({ isLoading: true }))
      renderLoginPage()
      expect(screen.getByRole('button', { name: 'Signing in…' })).toBeInTheDocument()
    })

    it('disables the submit button while isLoading is true', () => {
      mockUseAuthStore.mockReturnValue(makeStore({ isLoading: true }))
      renderLoginPage()
      expect(screen.getByRole('button', { name: 'Signing in…' })).toBeDisabled()
    })

    it('enables the submit button when isLoading is false', () => {
      renderLoginPage()
      expect(screen.getByRole('button', { name: 'Sign in' })).not.toBeDisabled()
    })
  })

  // ---------------------------------------------------------------------------
  // Error display
  // ---------------------------------------------------------------------------
  describe('Error display', () => {
    it('shows an error message when error is set in the store', () => {
      mockUseAuthStore.mockReturnValue(makeStore({ error: 'Invalid credentials' }))
      renderLoginPage()
      expect(screen.getByRole('alert')).toBeInTheDocument()
      expect(screen.getByRole('alert')).toHaveTextContent('Invalid credentials')
    })

    it('does not render an error alert when error is null', () => {
      renderLoginPage()
      expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    })

    it('calls clearError when the email field changes while an error is displayed', () => {
      const clearError = vi.fn()
      mockUseAuthStore.mockReturnValue(makeStore({ error: 'Bad creds', clearError }))
      renderLoginPage()
      fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'a@b.com' } })
      expect(clearError).toHaveBeenCalled()
    })

    it('calls clearError when the password field changes while an error is displayed', () => {
      const clearError = vi.fn()
      mockUseAuthStore.mockReturnValue(makeStore({ error: 'Bad creds', clearError }))
      renderLoginPage()
      fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'newpass' } })
      expect(clearError).toHaveBeenCalled()
    })

    it('does not call clearError on field change when error is null', () => {
      const clearError = vi.fn()
      mockUseAuthStore.mockReturnValue(makeStore({ error: null, clearError }))
      renderLoginPage()
      fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'x@y.com' } })
      expect(clearError).not.toHaveBeenCalled()
    })
  })

  // ---------------------------------------------------------------------------
  // Form submission
  // ---------------------------------------------------------------------------
  describe('Form submission', () => {
    it('calls login with email and password on form submit', async () => {
      const login = vi.fn().mockResolvedValue(undefined)
      mockUseAuthStore.mockReturnValue(makeStore({ login }))
      renderLoginPage()

      fireEvent.change(screen.getByLabelText('Email'),    { target: { value: 'admin@example.com' } })
      fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'secret' } })
      fireEvent.click(screen.getByRole('button', { name: 'Sign in' }))

      await waitFor(() => {
        expect(login).toHaveBeenCalledWith('admin@example.com', 'secret')
      })
    })

    it('calls login exactly once per submission', async () => {
      const login = vi.fn().mockResolvedValue(undefined)
      mockUseAuthStore.mockReturnValue(makeStore({ login }))
      renderLoginPage()

      fireEvent.change(screen.getByLabelText('Email'),    { target: { value: 'u@e.com' } })
      fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'pass' } })
      fireEvent.click(screen.getByRole('button', { name: 'Sign in' }))

      await waitFor(() => expect(login).toHaveBeenCalledTimes(1))
    })
  })

  // ---------------------------------------------------------------------------
  // Redirect on authentication
  // ---------------------------------------------------------------------------
  describe('Redirect on authentication', () => {
    it('redirects to "/" when isAuthenticated becomes true', async () => {
      mockUseAuthStore.mockReturnValue(makeStore({ isAuthenticated: true }))
      renderLoginPage()

      await waitFor(() => {
        expect(mockNavigate).toHaveBeenCalledWith('/', { replace: true })
      })
    })

    it('does not navigate when isAuthenticated is false', () => {
      renderLoginPage()
      expect(mockNavigate).not.toHaveBeenCalled()
    })
  })

  // ---------------------------------------------------------------------------
  // MFA step — rendering
  // ---------------------------------------------------------------------------
  describe('MFA step rendering', () => {
    it('renders the MFA heading when mfaPending is true', () => {
      mockUseAuthStore.mockReturnValue(makeStore({ mfaPending: true }))
      renderLoginPage()
      expect(screen.getByRole('heading', { name: 'Two-factor authentication' })).toBeInTheDocument()
    })

    it('does not render the password form when mfaPending is true', () => {
      mockUseAuthStore.mockReturnValue(makeStore({ mfaPending: true }))
      renderLoginPage()
      expect(screen.queryByLabelText('Password')).not.toBeInTheDocument()
    })

    it('renders the authentication code input when mfaPending is true', () => {
      mockUseAuthStore.mockReturnValue(makeStore({ mfaPending: true }))
      renderLoginPage()
      expect(screen.getByLabelText('Authentication code')).toBeInTheDocument()
    })

    it('renders the Verify submit button when mfaPending is true', () => {
      mockUseAuthStore.mockReturnValue(makeStore({ mfaPending: true }))
      renderLoginPage()
      expect(screen.getByRole('button', { name: 'Verify' })).toBeInTheDocument()
    })

    it('renders the "Use a backup code" link when mfaPending is true', () => {
      mockUseAuthStore.mockReturnValue(makeStore({ mfaPending: true }))
      renderLoginPage()
      expect(screen.getByText('Use a backup code')).toBeInTheDocument()
    })

    it('renders the "Back to sign in" link when mfaPending is true', () => {
      mockUseAuthStore.mockReturnValue(makeStore({ mfaPending: true }))
      renderLoginPage()
      expect(screen.getByText('Back to sign in')).toBeInTheDocument()
    })

    it('renders the password form (not MFA) when mfaPending is false', () => {
      mockUseAuthStore.mockReturnValue(makeStore({ mfaPending: false }))
      renderLoginPage()
      expect(screen.getByLabelText('Password')).toBeInTheDocument()
      expect(screen.queryByRole('heading', { name: 'Two-factor authentication' })).not.toBeInTheDocument()
    })
  })

  // ---------------------------------------------------------------------------
  // MFA step — submission
  // ---------------------------------------------------------------------------
  describe('MFA step submission', () => {
    it('calls submitMfa with the entered code', async () => {
      const submitMfa = vi.fn().mockResolvedValue(undefined)
      mockUseAuthStore.mockReturnValue(makeStore({ mfaPending: true, submitMfa }))
      renderLoginPage()

      fireEvent.change(screen.getByLabelText('Authentication code'), { target: { value: '123456' } })
      fireEvent.click(screen.getByRole('button', { name: 'Verify' }))

      await waitFor(() => {
        expect(submitMfa).toHaveBeenCalledWith('123456')
      })
    })

    it('shows "Verifying…" on the button while isLoading is true during MFA', () => {
      mockUseAuthStore.mockReturnValue(makeStore({ mfaPending: true, isLoading: true }))
      renderLoginPage()
      expect(screen.getByRole('button', { name: 'Verifying…' })).toBeInTheDocument()
    })

    it('disables the Verify button while isLoading is true', () => {
      mockUseAuthStore.mockReturnValue(makeStore({ mfaPending: true, isLoading: true }))
      renderLoginPage()
      expect(screen.getByRole('button', { name: 'Verifying…' })).toBeDisabled()
    })
  })

  // ---------------------------------------------------------------------------
  // MFA step — backup code toggle
  // ---------------------------------------------------------------------------
  describe('MFA backup code toggle', () => {
    it('switches label to "Backup code" when "Use a backup code" is clicked', () => {
      mockUseAuthStore.mockReturnValue(makeStore({ mfaPending: true }))
      renderLoginPage()

      fireEvent.click(screen.getByText('Use a backup code'))
      expect(screen.getByLabelText('Backup code')).toBeInTheDocument()
    })

    it('shows "Use authenticator app instead" after switching to backup mode', () => {
      mockUseAuthStore.mockReturnValue(makeStore({ mfaPending: true }))
      renderLoginPage()

      fireEvent.click(screen.getByText('Use a backup code'))
      expect(screen.getByText('Use authenticator app instead')).toBeInTheDocument()
    })
  })

  // ---------------------------------------------------------------------------
  // MFA step — cancel / back to sign in
  // ---------------------------------------------------------------------------
  describe('MFA step — cancel', () => {
    it('calls cancelMfa when "Back to sign in" is clicked', () => {
      const cancelMfa = vi.fn()
      mockUseAuthStore.mockReturnValue(makeStore({ mfaPending: true, cancelMfa }))
      renderLoginPage()

      fireEvent.click(screen.getByText('Back to sign in'))
      expect(cancelMfa).toHaveBeenCalled()
    })
  })

  // ---------------------------------------------------------------------------
  // MFA step — auto-focus
  // ---------------------------------------------------------------------------
  describe('MFA step — auto-focus', () => {
    it('the MFA code input receives focus when rendered', () => {
      mockUseAuthStore.mockReturnValue(makeStore({ mfaPending: true }))
      renderLoginPage()
      // React's autoFocus calls element.focus() — jsdom tracks this as document.activeElement
      expect(screen.getByLabelText('Authentication code')).toHaveFocus()
    })
  })

  // ---------------------------------------------------------------------------
  // MFA step — auto-advance (auto-submit on full TOTP code)
  // ---------------------------------------------------------------------------
  describe('MFA step — auto-advance', () => {
    it('calls submitMfa automatically when 6 digits are typed in TOTP mode', async () => {
      const submitMfa = vi.fn().mockResolvedValue(undefined)
      mockUseAuthStore.mockReturnValue(makeStore({ mfaPending: true, submitMfa }))
      renderLoginPage()

      fireEvent.change(screen.getByLabelText('Authentication code'), { target: { value: '123456' } })

      await waitFor(() => {
        expect(submitMfa).toHaveBeenCalledWith('123456')
      })
    })

    it('does not auto-submit in backup code mode (requires explicit submit)', async () => {
      const submitMfa = vi.fn().mockResolvedValue(undefined)
      mockUseAuthStore.mockReturnValue(makeStore({ mfaPending: true, submitMfa }))
      renderLoginPage()

      // Switch to backup code mode first
      fireEvent.click(screen.getByText('Use a backup code'))
      // Type an 8-char backup code — should NOT auto-submit
      fireEvent.change(screen.getByLabelText('Backup code'), { target: { value: 'AB12CD34' } })

      expect(submitMfa).not.toHaveBeenCalled()
    })

    it('does not auto-submit when fewer than 6 digits are entered', async () => {
      const submitMfa = vi.fn()
      mockUseAuthStore.mockReturnValue(makeStore({ mfaPending: true, submitMfa }))
      renderLoginPage()

      fireEvent.change(screen.getByLabelText('Authentication code'), { target: { value: '12345' } })

      expect(submitMfa).not.toHaveBeenCalled()
    })
  })
})
