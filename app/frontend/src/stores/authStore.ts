import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import { authApi } from '../lib/api'

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

  login: (email: string, password: string) => Promise<void>
  submitMfa: (code: string) => Promise<void>
  cancelMfa: () => void
  logout: () => Promise<void>
  clearError: () => void
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      user: null,
      token: null,
      isAuthenticated: false,
      isLoading: false,
      error: null,
      mfaPending: false,
      mfaToken: null,

      login: async (email, password) => {
        set({ isLoading: true, error: null })
        try {
          const data = await authApi.login(email, password)
          if (data.mfa_required && data.mfa_token) {
            set({ mfaPending: true, mfaToken: data.mfa_token, isLoading: false })
            return
          }
          localStorage.setItem('access_token', data.access_token)
          set({
            token: data.access_token,
            user: { email: data.email ?? email, role: data.role ?? 'analyst' },
            isAuthenticated: true,
            isLoading: false,
          })
        } catch (err: unknown) {
          const msg = (err as { response?: { data?: { detail?: string } } })
            ?.response?.data?.detail ?? 'Login failed'
          set({ error: msg, isLoading: false })
        }
      },

      submitMfa: async (code) => {
        const mfaToken = get().mfaToken
        if (!mfaToken) return
        set({ isLoading: true, error: null })
        try {
          const data = await authApi.mfaVerify(mfaToken, code)
          localStorage.setItem('access_token', data.access_token)
          set({
            token: data.access_token,
            user: { email: data.email ?? '', role: data.role ?? 'analyst' },
            isAuthenticated: true,
            isLoading: false,
            mfaPending: false,
            mfaToken: null,
          })
        } catch (err: unknown) {
          const msg = (err as { response?: { data?: { detail?: string } } })
            ?.response?.data?.detail ?? 'MFA verification failed'
          set({ error: msg, isLoading: false })
        }
      },

      cancelMfa: () => {
        set({ mfaPending: false, mfaToken: null, error: null })
      },

      logout: async () => {
        try {
          await authApi.logout()
        } finally {
          localStorage.removeItem('access_token')
          localStorage.removeItem('mxtac-auth')
          sessionStorage.clear()
          set({ user: null, token: null, isAuthenticated: false, mfaPending: false, mfaToken: null })
        }
      },

      clearError: () => set({ error: null }),
    }),
    {
      name: 'mxtac-auth',
      // Only persist identity — never persist full token in localStorage via zustand
      // (token is already in localStorage via direct set above for axios interceptor)
      partialize: (state) => ({ user: state.user, isAuthenticated: state.isAuthenticated }),
    },
  ),
)
