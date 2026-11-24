import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import { apiErrorMessage, authApi, type AuthStepResponse } from '../lib/api'
import { passwordErrorMessage } from '../lib/passwordPolicy'

interface AuthUser {
  email: string
  role: string
}

interface AuthState {
  user: AuthUser | null
  token: string | null
  isAuthenticated: boolean
  isLoading: boolean
  error: string | null
  mfaPending: boolean
  mfaToken: string | null
  /** True while the server requires a new password before it issues a session. */
  passwordChangePending: boolean
  /** One-time token for POST /auth/change-password. Kept in memory only, never persisted. */
  passwordChangeToken: string | null
  /** Email typed at sign-in, used when a later step's response does not name the account. */
  pendingEmail: string | null

  login: (email: string, password: string) => Promise<void>
  submitMfa: (code: string) => Promise<void>
  cancelMfa: () => void
  submitNewPassword: (newPassword: string) => Promise<void>
  cancelPasswordChange: () => void
  logout: () => Promise<void>
  clearError: () => void
}

const NO_PENDING_STEP = {
  mfaPending: false,
  mfaToken: null,
  passwordChangePending: false,
  passwordChangeToken: null,
} as const

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => {
      /**
       * Every sign-in call (login, password change, MFA) answers with one of three shapes:
       * a required password change, a required MFA code, or the session tokens.
       */
      const applyStep = (data: AuthStepResponse) => {
        if (data.password_change_required && data.password_change_token) {
          set({
            ...NO_PENDING_STEP,
            passwordChangePending: true,
            passwordChangeToken: data.password_change_token,
            isLoading: false,
          })
          return
        }
        if (data.mfa_required && data.mfa_token) {
          set({ ...NO_PENDING_STEP, mfaPending: true, mfaToken: data.mfa_token, isLoading: false })
          return
        }
        if (!data.access_token) throw new Error('The server did not return a session')
        localStorage.setItem('access_token', data.access_token)
        set({
          ...NO_PENDING_STEP,
          token: data.access_token,
          user: { email: data.email ?? get().pendingEmail ?? '', role: data.role ?? 'analyst' },
          pendingEmail: null,
          isAuthenticated: true,
          isLoading: false,
        })
      }

      return {
        user: null,
        token: null,
        isAuthenticated: false,
        isLoading: false,
        error: null,
        ...NO_PENDING_STEP,
        pendingEmail: null,

        login: async (email, password) => {
          set({ isLoading: true, error: null, pendingEmail: email })
          try {
            applyStep(await authApi.login(email, password))
          } catch (err: unknown) {
            set({ error: apiErrorMessage(err, 'Login failed'), isLoading: false })
          }
        },

        submitMfa: async (code) => {
          const mfaToken = get().mfaToken
          if (!mfaToken) return
          set({ isLoading: true, error: null })
          try {
            applyStep(await authApi.mfaVerify(mfaToken, code))
          } catch (err: unknown) {
            set({ error: apiErrorMessage(err, 'MFA verification failed'), isLoading: false })
          }
        },

        cancelMfa: () => {
          set({ ...NO_PENDING_STEP, pendingEmail: null, error: null })
        },

        submitNewPassword: async (newPassword) => {
          const token = get().passwordChangeToken
          if (!token) return
          set({ isLoading: true, error: null })
          try {
            applyStep(await authApi.changePasswordWithToken(token, newPassword))
          } catch (err: unknown) {
            set({ error: passwordErrorMessage(err, 'Could not set the new password'), isLoading: false })
          }
        },

        cancelPasswordChange: () => {
          set({ ...NO_PENDING_STEP, pendingEmail: null, error: null })
        },

        logout: async () => {
          try {
            await authApi.logout()
          } finally {
            localStorage.removeItem('access_token')
            localStorage.removeItem('mxtac-auth')
            sessionStorage.clear()
            set({ user: null, token: null, isAuthenticated: false, ...NO_PENDING_STEP, pendingEmail: null })
          }
        },

        clearError: () => set({ error: null }),
      }
    },
    {
      name: 'mxtac-auth',
      // Only persist identity — never persist full token in localStorage via zustand
      // (token is already in localStorage via direct set above for axios interceptor).
      // The MFA and password-change tokens are deliberately left out: memory only.
      partialize: (state) => ({ user: state.user, isAuthenticated: state.isAuthenticated }),
    },
  ),
)
