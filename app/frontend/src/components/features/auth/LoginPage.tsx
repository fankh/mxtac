import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuthStore } from '../../../stores/authStore'

export function LoginPage() {
  const navigate = useNavigate()
  const {
    login, submitMfa, cancelMfa,
    isLoading, error, isAuthenticated, mfaPending,
    clearError,
  } = useAuthStore()

  const [email, setEmail]       = useState('')
  const [password, setPassword] = useState('')
  const [mfaCode, setMfaCode]   = useState('')
  const [useBackup, setUseBackup] = useState(false)

  useEffect(() => {
    if (isAuthenticated) navigate('/', { replace: true })
  }, [isAuthenticated, navigate])

  async function handlePasswordSubmit(e: React.FormEvent) {
    e.preventDefault()
    await login(email, password)
  }

  async function handleMfaSubmit(e: React.FormEvent) {
    e.preventDefault()
    await submitMfa(mfaCode)
  }

  function handleCancelMfa() {
    setMfaCode('')
    setUseBackup(false)
    cancelMfa()
  }

  return (
    <div className="min-h-screen bg-page flex items-center justify-center">
      <div className="bg-surface border border-border rounded-lg shadow-lg w-full max-w-sm p-8">

        {/* Logo */}
        <div className="flex items-center gap-3 mb-8">
          <div className="w-8 h-8 rounded-[6px] bg-blue flex items-center justify-center text-white text-sm font-bold">
            M
          </div>
          <span className="text-text-primary font-semibold text-lg">MxTac</span>
        </div>

        {mfaPending ? (
          <>
            <h1 className="text-text-primary font-semibold text-xl mb-1">Two-factor authentication</h1>
            <p className="text-text-muted text-sm mb-6">
              {useBackup
                ? 'Enter one of your backup codes.'
                : 'Enter the 6-digit code from your authenticator app.'}
            </p>

            <form onSubmit={handleMfaSubmit} className="flex flex-col gap-4">
              <div className="flex flex-col gap-1">
                <label htmlFor="mfa-code" className="text-text-secondary text-xs font-medium">
                  {useBackup ? 'Backup code' : 'Authentication code'}
                </label>
                <input
                  id="mfa-code"
                  type="text"
                  autoComplete="one-time-code"
                  autoFocus
                  required
                  value={mfaCode}
                  onChange={e => {
                    const val = e.target.value
                    setMfaCode(val)
                    if (error) clearError()
                    // Auto-advance: submit when the full code is entered (TOTP only)
                    if (!useBackup && val.length === 6) {
                      submitMfa(val)
                    }
                  }}
                  className="border border-border rounded-md px-3 py-2 text-sm text-text-primary bg-surface
                             focus:outline-none focus:border-blue focus:ring-1 focus:ring-blue placeholder:text-text-muted
                             tracking-widest text-center"
                  placeholder={useBackup ? 'XXXXXXXX' : '000000'}
                  maxLength={useBackup ? 8 : 6}
                />
              </div>

              {error && (
                <p role="alert" className="text-xs text-crit-text bg-crit-bg rounded-md px-3 py-2">
                  {error}
                </p>
              )}

              <button
                type="submit"
                disabled={isLoading}
                className="bg-blue text-white rounded-md py-2 text-sm font-medium
                           hover:bg-blue-dark disabled:opacity-50 disabled:cursor-not-allowed
                           transition-colors mt-1"
              >
                {isLoading ? 'Verifying…' : 'Verify'}
              </button>
            </form>

            <div className="mt-4 flex flex-col gap-2 items-center">
              <button
                type="button"
                onClick={() => { setUseBackup(b => !b); setMfaCode(''); if (error) clearError() }}
                className="text-xs text-blue hover:underline"
              >
                {useBackup ? 'Use authenticator app instead' : 'Use a backup code'}
              </button>
              <button
                type="button"
                onClick={handleCancelMfa}
                className="text-xs text-text-muted hover:underline"
              >
                Back to sign in
              </button>
            </div>
          </>
        ) : (
          <>
            <h1 className="text-text-primary font-semibold text-xl mb-1">Sign in</h1>
            <p className="text-text-muted text-sm mb-6">MITRE ATT&CK Security Platform</p>

            <form onSubmit={handlePasswordSubmit} className="flex flex-col gap-4">
              <div className="flex flex-col gap-1">
                <label htmlFor="email" className="text-text-secondary text-xs font-medium">
                  Email
                </label>
                <input
                  id="email"
                  type="email"
                  autoComplete="email"
                  required
                  value={email}
                  onChange={e => { setEmail(e.target.value); if (error) clearError() }}
                  className="border border-border rounded-md px-3 py-2 text-sm text-text-primary bg-surface
                             focus:outline-none focus:border-blue focus:ring-1 focus:ring-blue placeholder:text-text-muted"
                  placeholder="you@example.com"
                />
              </div>

              <div className="flex flex-col gap-1">
                <label htmlFor="password" className="text-text-secondary text-xs font-medium">
                  Password
                </label>
                <input
                  id="password"
                  type="password"
                  autoComplete="current-password"
                  required
                  value={password}
                  onChange={e => { setPassword(e.target.value); if (error) clearError() }}
                  className="border border-border rounded-md px-3 py-2 text-sm text-text-primary bg-surface
                             focus:outline-none focus:border-blue focus:ring-1 focus:ring-blue placeholder:text-text-muted"
                  placeholder="••••••••"
                />
              </div>

              {error && (
                <p role="alert" className="text-xs text-crit-text bg-crit-bg rounded-md px-3 py-2">
                  {error}
                </p>
              )}

              <button
                type="submit"
                disabled={isLoading}
                className="bg-blue text-white rounded-md py-2 text-sm font-medium
                           hover:bg-blue-dark disabled:opacity-50 disabled:cursor-not-allowed
                           transition-colors mt-1"
              >
                {isLoading ? 'Signing in…' : 'Sign in'}
              </button>
            </form>
          </>
        )}
      </div>
    </div>
  )
}
