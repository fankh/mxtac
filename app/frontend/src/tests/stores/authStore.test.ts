import { describe, it, expect, beforeEach, vi } from 'vitest'

// vi.mock is hoisted — runs before imports
vi.mock('../../lib/api', () => ({
  authApi: {
    login: vi.fn(),
    mfaVerify: vi.fn(),
    logout: vi.fn(),
  },
}))

import { useAuthStore } from '../../stores/authStore'
import { authApi } from '../../lib/api'

const loginMock = authApi.login as ReturnType<typeof vi.fn>
const mfaVerifyMock = authApi.mfaVerify as ReturnType<typeof vi.fn>
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
})
