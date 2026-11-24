import { describe, it, expect, beforeEach, vi } from 'vitest'

// vi.mock is hoisted — runs before imports
vi.mock('../../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof ApiModule>()),
  authApi: {
    login: vi.fn(),
    mfaVerify: vi.fn(),
    changePasswordWithToken: vi.fn(),
    logout: vi.fn(),
  },
}))

import { useAuthStore } from '../../stores/authStore'
import type * as ApiModule from '../../lib/api'
import { authApi } from '../../lib/api'

const loginMock = authApi.login as ReturnType<typeof vi.fn>
const mfaVerifyMock = authApi.mfaVerify as ReturnType<typeof vi.fn>
const changePasswordMock = authApi.changePasswordWithToken as ReturnType<typeof vi.fn>
const logoutMock = authApi.logout as ReturnType<typeof vi.fn>

describe('authStore', () => {
  beforeEach(() => {
    useAuthStore.setState({
      user: null,
      token: null,
      isAuthenticated: false,
      isLoading: false,
      error: null,
      mfaPending: false,
      mfaToken: null,
      passwordChangePending: false,
      passwordChangeToken: null,
      pendingEmail: null,
    })
    vi.clearAllMocks()
    localStorage.clear()
  })

  // ---------------------------------------------------------------------------
  // Initial state
  // ---------------------------------------------------------------------------
  describe('initial state', () => {
    it('user is null by default', () => {
      expect(useAuthStore.getState().user).toBeNull()
    })

    it('token is null by default', () => {
      expect(useAuthStore.getState().token).toBeNull()
    })

    it('isAuthenticated is false by default', () => {
      expect(useAuthStore.getState().isAuthenticated).toBe(false)
    })

    it('isLoading is false by default', () => {
      expect(useAuthStore.getState().isLoading).toBe(false)
    })

    it('error is null by default', () => {
      expect(useAuthStore.getState().error).toBeNull()
    })
  })

  // ---------------------------------------------------------------------------
  // login
  // ---------------------------------------------------------------------------
  describe('login', () => {
    it('sets isLoading=true while the request is in-flight', async () => {
      let settle!: (v: unknown) => void
      loginMock.mockImplementationOnce(
        () => new Promise((resolve) => { settle = resolve }),
      )

      const promise = useAuthStore.getState().login('u@e.com', 'pass')
      expect(useAuthStore.getState().isLoading).toBe(true)

      settle({ access_token: 'tok', email: 'u@e.com' })
      await promise
    })

    it('clears a previous error at the start of a login attempt', async () => {
      useAuthStore.setState({ error: 'old error' })
      loginMock.mockResolvedValueOnce({ access_token: 't', email: 'u@e.com', role: 'analyst' })

      await useAuthStore.getState().login('u@e.com', 'pass')
      expect(useAuthStore.getState().error).toBeNull()
    })

    it('sets token, user, and isAuthenticated on success', async () => {
      loginMock.mockResolvedValueOnce({
        access_token: 'tok-abc',
        email: 'admin@example.com',
        role: 'admin',
      })

      await useAuthStore.getState().login('admin@example.com', 'secret')

      const state = useAuthStore.getState()
      expect(state.token).toBe('tok-abc')
      expect(state.user).toEqual({ email: 'admin@example.com', role: 'admin' })
      expect(state.isAuthenticated).toBe(true)
      expect(state.isLoading).toBe(false)
    })

    it('stores token in localStorage on success', async () => {
      loginMock.mockResolvedValueOnce({
        access_token: 'my-jwt',
        email: 'u@e.com',
        role: 'analyst',
      })

      await useAuthStore.getState().login('u@e.com', 'pass')
      expect(localStorage.getItem('access_token')).toBe('my-jwt')
    })

    it('falls back to the login email when the API response omits email', async () => {
      loginMock.mockResolvedValueOnce({ access_token: 'tok', role: 'analyst' })

      await useAuthStore.getState().login('fallback@example.com', 'pass')
      expect(useAuthStore.getState().user?.email).toBe('fallback@example.com')
    })

    it('falls back to role "analyst" when the API response omits role', async () => {
      loginMock.mockResolvedValueOnce({ access_token: 'tok', email: 'u@e.com' })

      await useAuthStore.getState().login('u@e.com', 'pass')
      expect(useAuthStore.getState().user?.role).toBe('analyst')
    })

    it('sets error from API response.data.detail on failure', async () => {
      loginMock.mockRejectedValueOnce({
        response: { data: { detail: 'Invalid credentials' } },
      })

      await useAuthStore.getState().login('u@e.com', 'wrong')
      expect(useAuthStore.getState().error).toBe('Invalid credentials')
    })

    it('uses "Login failed" fallback when the error has no detail', async () => {
      loginMock.mockRejectedValueOnce(new Error('Network error'))

      await useAuthStore.getState().login('u@e.com', 'wrong')
      expect(useAuthStore.getState().error).toBe('Login failed')
    })

    it('leaves isAuthenticated=false and sets isLoading=false after failure', async () => {
      loginMock.mockRejectedValueOnce({ response: { data: { detail: 'Bad creds' } } })

      await useAuthStore.getState().login('u@e.com', 'wrong')

      const state = useAuthStore.getState()
      expect(state.isLoading).toBe(false)
      expect(state.isAuthenticated).toBe(false)
    })
  })

  // ---------------------------------------------------------------------------
  // logout
  // ---------------------------------------------------------------------------
  describe('logout', () => {
    it('clears user, token, and isAuthenticated', async () => {
      useAuthStore.setState({
        user: { email: 'u@e.com', role: 'analyst' },
        token: 'tok',
        isAuthenticated: true,
      })
      logoutMock.mockResolvedValueOnce({})

      await useAuthStore.getState().logout()

      const state = useAuthStore.getState()
      expect(state.user).toBeNull()
      expect(state.token).toBeNull()
      expect(state.isAuthenticated).toBe(false)
    })

    it('removes access_token from localStorage', async () => {
      localStorage.setItem('access_token', 'stored-tok')
      logoutMock.mockResolvedValueOnce({})

      await useAuthStore.getState().logout()
      expect(localStorage.getItem('access_token')).toBeNull()
    })

    it('still clears auth state even when the logout API call throws', async () => {
      useAuthStore.setState({
        isAuthenticated: true,
        user: { email: 'u@e.com', role: 'analyst' },
      })
      logoutMock.mockRejectedValueOnce(new Error('Network error'))

      // logout uses try/finally — the error propagates but the finally block still clears state
      try {
        await useAuthStore.getState().logout()
      } catch {
        // expected: error re-throws after finally runs
      }

      expect(useAuthStore.getState().isAuthenticated).toBe(false)
      expect(useAuthStore.getState().user).toBeNull()
    })
  })

  // ---------------------------------------------------------------------------
  // clearError
  // ---------------------------------------------------------------------------
  describe('clearError', () => {
    it('sets error to null', () => {
      useAuthStore.setState({ error: 'Some error' })
      useAuthStore.getState().clearError()
      expect(useAuthStore.getState().error).toBeNull()
    })

    it('is a no-op when error is already null', () => {
      useAuthStore.getState().clearError()
      expect(useAuthStore.getState().error).toBeNull()
    })
  })

  // ---------------------------------------------------------------------------
  // MFA initial state
  // ---------------------------------------------------------------------------
  describe('MFA initial state', () => {
    it('mfaPending is false by default', () => {
      expect(useAuthStore.getState().mfaPending).toBe(false)
    })

    it('mfaToken is null by default', () => {
      expect(useAuthStore.getState().mfaToken).toBeNull()
    })
  })

  // ---------------------------------------------------------------------------
  // login — MFA required branch
  // ---------------------------------------------------------------------------
  describe('login — MFA required', () => {
    it('sets mfaPending=true when API returns mfa_required', async () => {
      loginMock.mockResolvedValueOnce({ mfa_required: true, mfa_token: 'mfa-jwt' })

      await useAuthStore.getState().login('u@e.com', 'pass')
      expect(useAuthStore.getState().mfaPending).toBe(true)
    })

    it('stores the mfa_token when API returns mfa_required', async () => {
      loginMock.mockResolvedValueOnce({ mfa_required: true, mfa_token: 'mfa-jwt-abc' })

      await useAuthStore.getState().login('u@e.com', 'pass')
      expect(useAuthStore.getState().mfaToken).toBe('mfa-jwt-abc')
    })

    it('does NOT set isAuthenticated when MFA is required', async () => {
      loginMock.mockResolvedValueOnce({ mfa_required: true, mfa_token: 'mfa-jwt' })

      await useAuthStore.getState().login('u@e.com', 'pass')
      expect(useAuthStore.getState().isAuthenticated).toBe(false)
    })

    it('sets isLoading=false after MFA pending state is set', async () => {
      loginMock.mockResolvedValueOnce({ mfa_required: true, mfa_token: 'mfa-jwt' })

      await useAuthStore.getState().login('u@e.com', 'pass')
      expect(useAuthStore.getState().isLoading).toBe(false)
    })

    it('does not store access_token in localStorage when MFA is required', async () => {
      loginMock.mockResolvedValueOnce({ mfa_required: true, mfa_token: 'mfa-jwt' })

      await useAuthStore.getState().login('u@e.com', 'pass')
      expect(localStorage.getItem('access_token')).toBeNull()
    })
  })

  // ---------------------------------------------------------------------------
  // submitMfa
  // ---------------------------------------------------------------------------
  describe('submitMfa', () => {
    beforeEach(() => {
      useAuthStore.setState({ mfaPending: true, mfaToken: 'mfa-jwt-token' })
    })

    it('sets isAuthenticated=true on success', async () => {
      mfaVerifyMock.mockResolvedValueOnce({ access_token: 'access-tok', role: 'analyst' })

      await useAuthStore.getState().submitMfa('123456')
      expect(useAuthStore.getState().isAuthenticated).toBe(true)
    })

    it('stores the access_token in localStorage on success', async () => {
      mfaVerifyMock.mockResolvedValueOnce({ access_token: 'mfa-access-tok' })

      await useAuthStore.getState().submitMfa('123456')
      expect(localStorage.getItem('access_token')).toBe('mfa-access-tok')
    })

    it('clears mfaPending and mfaToken on success', async () => {
      mfaVerifyMock.mockResolvedValueOnce({ access_token: 'tok', role: 'analyst' })

      await useAuthStore.getState().submitMfa('123456')
      expect(useAuthStore.getState().mfaPending).toBe(false)
      expect(useAuthStore.getState().mfaToken).toBeNull()
    })

    it('sets error from detail on failure', async () => {
      mfaVerifyMock.mockRejectedValueOnce({ response: { data: { detail: 'Invalid MFA code' } } })

      await useAuthStore.getState().submitMfa('000000')
      expect(useAuthStore.getState().error).toBe('Invalid MFA code')
    })

    it('falls back to "MFA verification failed" when error has no detail', async () => {
      mfaVerifyMock.mockRejectedValueOnce(new Error('Network error'))

      await useAuthStore.getState().submitMfa('000000')
      expect(useAuthStore.getState().error).toBe('MFA verification failed')
    })

    it('leaves isAuthenticated=false on failure', async () => {
      mfaVerifyMock.mockRejectedValueOnce({ response: { data: { detail: 'Invalid MFA code' } } })

      await useAuthStore.getState().submitMfa('000000')
      expect(useAuthStore.getState().isAuthenticated).toBe(false)
    })

    it('is a no-op when mfaToken is null', async () => {
      useAuthStore.setState({ mfaToken: null })

      await useAuthStore.getState().submitMfa('123456')
      expect(mfaVerifyMock).not.toHaveBeenCalled()
    })
  })

  // ---------------------------------------------------------------------------
  // cancelMfa
  // ---------------------------------------------------------------------------
  describe('cancelMfa', () => {
    it('clears mfaPending', () => {
      useAuthStore.setState({ mfaPending: true, mfaToken: 'tok', error: 'err' })
      useAuthStore.getState().cancelMfa()
      expect(useAuthStore.getState().mfaPending).toBe(false)
    })

    it('clears mfaToken', () => {
      useAuthStore.setState({ mfaPending: true, mfaToken: 'tok' })
      useAuthStore.getState().cancelMfa()
      expect(useAuthStore.getState().mfaToken).toBeNull()
    })

    it('clears error', () => {
      useAuthStore.setState({ error: 'some mfa error' })
      useAuthStore.getState().cancelMfa()
      expect(useAuthStore.getState().error).toBeNull()
    })
  })

  // ---------------------------------------------------------------------------
  // login — password change required branch
  // ---------------------------------------------------------------------------
  describe('login — password change required', () => {
    const REQUIRED = { password_change_required: true, password_change_token: 'pc-jwt' }

    it('is not pending by default', () => {
      expect(useAuthStore.getState().passwordChangePending).toBe(false)
      expect(useAuthStore.getState().passwordChangeToken).toBeNull()
    })

    it('keeps the token and waits for a new password', async () => {
      loginMock.mockResolvedValueOnce(REQUIRED)

      await useAuthStore.getState().login('new@e.com', 'Temp-Passw0rd')

      const state = useAuthStore.getState()
      expect(state.passwordChangePending).toBe(true)
      expect(state.passwordChangeToken).toBe('pc-jwt')
      expect(state.isAuthenticated).toBe(false)
      expect(state.isLoading).toBe(false)
      expect(state.error).toBeNull()
      expect(state.mfaPending).toBe(false)
    })

    it('keeps the token in memory only', async () => {
      loginMock.mockResolvedValueOnce(REQUIRED)

      await useAuthStore.getState().login('new@e.com', 'Temp-Passw0rd')

      expect(localStorage.getItem('access_token')).toBeNull()
      const stored = Object.keys(localStorage).map((k) => localStorage.getItem(k) ?? '').join(' ')
      expect(stored).not.toContain('pc-jwt')
      expect(stored).not.toContain('Temp-Passw0rd')
      expect(Object.keys(sessionStorage)).toHaveLength(0)
    })
  })

  // ---------------------------------------------------------------------------
  // submitNewPassword
  // ---------------------------------------------------------------------------
  describe('submitNewPassword', () => {
    beforeEach(() => {
      useAuthStore.setState({ passwordChangePending: true, passwordChangeToken: 'pc-jwt', pendingEmail: 'new@e.com' })
    })

    it('sends the token and the new password to POST /auth/change-password', async () => {
      changePasswordMock.mockResolvedValueOnce({ access_token: 'tok', email: 'new@e.com', role: 'hunter' })

      await useAuthStore.getState().submitNewPassword('Brand-New-Passw0rd')

      expect(changePasswordMock).toHaveBeenCalledTimes(1)
      expect(changePasswordMock).toHaveBeenCalledWith('pc-jwt', 'Brand-New-Passw0rd')
    })

    it('signs the user in exactly as a normal login does', async () => {
      changePasswordMock.mockResolvedValueOnce({ access_token: 'session-tok', email: 'new@e.com', role: 'hunter' })

      await useAuthStore.getState().submitNewPassword('Brand-New-Passw0rd')

      const state = useAuthStore.getState()
      expect(state.isAuthenticated).toBe(true)
      expect(state.token).toBe('session-tok')
      expect(state.user).toEqual({ email: 'new@e.com', role: 'hunter' })
      expect(localStorage.getItem('access_token')).toBe('session-tok')
      expect(state.passwordChangePending).toBe(false)
      expect(state.passwordChangeToken).toBeNull()
      expect(state.isLoading).toBe(false)
    })

    it('falls back to the email typed at sign-in when the response omits it', async () => {
      changePasswordMock.mockResolvedValueOnce({ access_token: 'tok' })

      await useAuthStore.getState().submitNewPassword('Brand-New-Passw0rd')

      expect(useAuthStore.getState().user).toEqual({ email: 'new@e.com', role: 'analyst' })
    })

    it('continues with the MFA step when the server asks for it', async () => {
      changePasswordMock.mockResolvedValueOnce({ mfa_required: true, mfa_token: 'mfa-jwt' })

      await useAuthStore.getState().submitNewPassword('Brand-New-Passw0rd')

      const state = useAuthStore.getState()
      expect(state.passwordChangePending).toBe(false)
      expect(state.passwordChangeToken).toBeNull()
      expect(state.mfaPending).toBe(true)
      expect(state.mfaToken).toBe('mfa-jwt')
      expect(state.isAuthenticated).toBe(false)
      expect(localStorage.getItem('access_token')).toBeNull()
    })

    it('finishes the sign-in after the MFA step that follows a password change', async () => {
      changePasswordMock.mockResolvedValueOnce({ mfa_required: true, mfa_token: 'mfa-jwt' })
      mfaVerifyMock.mockResolvedValueOnce({ access_token: 'final-tok', role: 'admin' })

      await useAuthStore.getState().submitNewPassword('Brand-New-Passw0rd')
      await useAuthStore.getState().submitMfa('123456')

      expect(mfaVerifyMock).toHaveBeenCalledWith('mfa-jwt', '123456')
      const state = useAuthStore.getState()
      expect(state.isAuthenticated).toBe(true)
      expect(state.user).toEqual({ email: 'new@e.com', role: 'admin' })
    })

    it('shows the server message and stays on the step when the password is rejected', async () => {
      changePasswordMock.mockRejectedValueOnce({
        response: { data: { detail: 'Cannot reuse one of your last 2 passwords' } },
      })

      await useAuthStore.getState().submitNewPassword('Temp-Passw0rd')

      const state = useAuthStore.getState()
      expect(state.error).toBe('Cannot reuse one of your last 2 passwords')
      expect(state.passwordChangePending).toBe(true)
      expect(state.passwordChangeToken).toBe('pc-jwt')
      expect(state.isAuthenticated).toBe(false)
      expect(state.isLoading).toBe(false)
    })

    it('reads the policy message out of a 422 validation answer', async () => {
      changePasswordMock.mockRejectedValueOnce({
        response: { data: { detail: [{ loc: ['body', 'new_password'], msg: 'Value error, Password must contain at least 3 of the following character types: uppercase letters, lowercase letters, digits, special characters' }] } },
      })

      await useAuthStore.getState().submitNewPassword('alllowercase')

      expect(useAuthStore.getState().error).toBe(
        'Password must contain at least 3 of the following character types: uppercase letters, lowercase letters, digits, special characters',
      )
    })

    it('falls back to a generic message when the error has no detail', async () => {
      changePasswordMock.mockRejectedValueOnce(new Error('Network error'))

      await useAuthStore.getState().submitNewPassword('Brand-New-Passw0rd')

      expect(useAuthStore.getState().error).toBe('Could not set the new password')
    })

    it('is a no-op without a token', async () => {
      useAuthStore.setState({ passwordChangeToken: null })

      await useAuthStore.getState().submitNewPassword('Brand-New-Passw0rd')

      expect(changePasswordMock).not.toHaveBeenCalled()
    })
  })

  // ---------------------------------------------------------------------------
  // cancelPasswordChange
  // ---------------------------------------------------------------------------
  describe('cancelPasswordChange', () => {
    it('drops the token and returns to sign-in', () => {
      useAuthStore.setState({ passwordChangePending: true, passwordChangeToken: 'pc-jwt', pendingEmail: 'new@e.com', error: 'err' })

      useAuthStore.getState().cancelPasswordChange()

      const state = useAuthStore.getState()
      expect(state.passwordChangePending).toBe(false)
      expect(state.passwordChangeToken).toBeNull()
      expect(state.pendingEmail).toBeNull()
      expect(state.error).toBeNull()
      expect(state.isAuthenticated).toBe(false)
    })
  })

  // ---------------------------------------------------------------------------
  // logout
  // ---------------------------------------------------------------------------
  describe('logout — pending steps', () => {
    it('drops a pending password-change token', async () => {
      logoutMock.mockResolvedValueOnce(undefined)
      useAuthStore.setState({ passwordChangePending: true, passwordChangeToken: 'pc-jwt' })

      await useAuthStore.getState().logout()

      expect(useAuthStore.getState().passwordChangePending).toBe(false)
      expect(useAuthStore.getState().passwordChangeToken).toBeNull()
    })
  })
})
