import { useEffect, useState, type FormEvent } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { ExternalLink } from 'lucide-react'
import { useAuthStore } from '../../../stores/authStore'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { KYRA_MDR_URL, MXTAC_REPO_URL } from '@/lib/links'
import { PASSWORD_POLICY_HINT, passwordProblem } from '@/lib/passwordPolicy'
import { RETURN_TO_KEY, SESSION_ENDED_KEY } from '@/lib/api'

/** A stored return path is only used when it is a path of this application. */
function safeReturnPath(path: string | null): string | null {
  if (!path || !path.startsWith('/') || path.startsWith('//') || path.startsWith('/login')) return null
  return path
}

export function LoginPage() {
  const navigate = useNavigate()
  // ProtectedRoute passes the page that was asked for while signed out.
  const from = (useLocation().state as { from?: { pathname?: string; search?: string } } | null)?.from
  // Left behind by the API client when the server ended the session (lib/api.ts, endSession):
  // the notice to show and the page that was open, query string included.
  const [sessionEnded] = useState(() => sessionStorage.getItem(SESSION_ENDED_KEY) === '1')
  const [returnTo] = useState(() => safeReturnPath(sessionStorage.getItem(RETURN_TO_KEY)))
  const target = from?.pathname && !from.pathname.startsWith('/login')
    ? `${from.pathname}${from.search ?? ''}`
    : returnTo ?? '/'
  const {
    login, submitMfa, cancelMfa, submitNewPassword, cancelPasswordChange,
    isLoading, error, isAuthenticated, mfaPending, passwordChangePending,
    clearError,
  } = useAuthStore()

  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [mfaCode, setMfaCode] = useState('')
  const [useBackup, setUseBackup] = useState(false)
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  // Problem found in the browser before anything is sent; the server's answer arrives as `error`.
  const [localError, setLocalError] = useState('')

  useEffect(() => {
    if (isAuthenticated) navigate(target, { replace: true })
  }, [isAuthenticated, navigate, target])

  // Both values are held in state above; the stored copies are single use.
  useEffect(() => {
    sessionStorage.removeItem(SESSION_ENDED_KEY)
    sessionStorage.removeItem(RETURN_TO_KEY)
  }, [])

  async function handlePasswordSubmit(e: FormEvent) {
    e.preventDefault()
    await login(email, password)
  }

  async function handleMfaSubmit(e: FormEvent) {
    e.preventDefault()
    await submitMfa(mfaCode)
  }

  function handleCancelMfa() {
    setMfaCode('')
    setUseBackup(false)
    cancelMfa()
  }

  async function handleNewPasswordSubmit(e: FormEvent) {
    e.preventDefault()
    const problem = passwordProblem(newPassword)
      || (newPassword !== confirmPassword ? 'The passwords do not match' : '')
      || (newPassword === password ? 'The new password must differ from the current one' : '')
    if (problem) {
      if (error) clearError()
      setLocalError(problem)
      return
    }
    setLocalError('')
    await submitNewPassword(newPassword)
  }

  function handleCancelPasswordChange() {
    setPassword('')
    cancelPasswordChange()
  }

  // The typed passwords are no longer needed once the step is over (signed in, MFA next, or cancelled).
  useEffect(() => {
    if (passwordChangePending) return
    setNewPassword('')
    setConfirmPassword('')
    setLocalError('')
  }, [passwordChangePending])

  const shownError = localError || error
  const errorBox = shownError && (
    <p role="alert" className="sev-critical rounded-md border px-3 py-2 text-[12px]">
      {shownError}
    </p>
  )

  const newPasswordField = (id: string, label: string, value: string, onChange: (v: string) => void, autoFocus = false) => (
    <div className="flex flex-col gap-1.5">
      <Label htmlFor={id} className="text-[12px] font-medium">{label}</Label>
      <Input
        id={id}
        type="password"
        autoComplete="new-password"
        autoFocus={autoFocus}
        required
        maxLength={128}
        value={value}
        onChange={(e) => {
          onChange(e.target.value)
          setLocalError('')
          if (error) clearError()
        }}
      />
    </div>
  )

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-background px-4">
      <div className="w-full max-w-sm rounded-lg border bg-card p-8 shadow-sm">
        <div className="mb-8 flex items-center gap-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary text-sm font-bold text-primary-foreground">
            M
          </div>
          <span className="text-lg font-semibold">MxTac</span>
        </div>

        {passwordChangePending ? (
          <>
            <h1 className="mb-1 text-xl font-semibold">Set a new password</h1>
            <p className="mb-6 text-sm text-muted-foreground">
              Your current password is temporary or has expired. Choose a new one to finish signing in.
            </p>

            <form onSubmit={handleNewPasswordSubmit} className="flex flex-col gap-4" noValidate>
              {newPasswordField('new-password', 'New password', newPassword, setNewPassword, true)}
              {newPasswordField('confirm-password', 'Confirm new password', confirmPassword, setConfirmPassword)}
              <p className="text-[11px] text-muted-foreground">{PASSWORD_POLICY_HINT}</p>

              {errorBox}

              <Button type="submit" disabled={isLoading} className="mt-1">
                {isLoading ? 'Saving…' : 'Set password and sign in'}
              </Button>
            </form>

            <div className="mt-4 flex flex-col items-center gap-1">
              <Button
                type="button" variant="link" size="sm" className="text-muted-foreground"
                onClick={handleCancelPasswordChange}
              >
                Back to sign in
              </Button>
            </div>
          </>
        ) : mfaPending ? (
          <>
            <h1 className="mb-1 text-xl font-semibold">Two-factor authentication</h1>
            <p className="mb-6 text-sm text-muted-foreground">
              {useBackup ? 'Enter one of your backup codes.' : 'Enter the 6-digit code from your authenticator app.'}
            </p>

            <form onSubmit={handleMfaSubmit} className="flex flex-col gap-4">
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="mfa-code" className="text-[12px] font-medium">
                  {useBackup ? 'Backup code' : 'Authentication code'}
                </Label>
                <Input
                  id="mfa-code"
                  type="text"
                  autoComplete="one-time-code"
                  autoFocus
                  required
                  value={mfaCode}
                  onChange={(e) => {
                    const val = e.target.value
                    setMfaCode(val)
                    if (error) clearError()
                    // Submit as soon as the full authenticator code is typed
                    if (!useBackup && val.length === 6) void submitMfa(val)
                  }}
                  className="text-center tracking-widest"
                  placeholder={useBackup ? 'XXXXXXXX' : '000000'}
                  maxLength={useBackup ? 8 : 6}
                />
              </div>

              {errorBox}

              <Button type="submit" disabled={isLoading} className="mt-1">
                {isLoading ? 'Verifying…' : 'Verify'}
              </Button>
            </form>

            <div className="mt-4 flex flex-col items-center gap-1">
              <Button
                type="button"
                variant="link"
                size="sm"
                onClick={() => { setUseBackup((b) => !b); setMfaCode(''); if (error) clearError() }}
              >
                {useBackup ? 'Use authenticator app instead' : 'Use a backup code'}
              </Button>
              <Button type="button" variant="link" size="sm" className="text-muted-foreground" onClick={handleCancelMfa}>
                Back to sign in
              </Button>
            </div>
          </>
        ) : (
          <>
            <h1 className="mb-1 text-xl font-semibold">Sign in</h1>
            <p className="mb-6 text-sm text-muted-foreground">Open-source ATT&amp;CK detection platform</p>

            {sessionEnded && (
              <p role="status" className="sev-medium mb-4 rounded-md border px-3 py-2 text-[12px]">
                Your session has ended. Sign in again.
              </p>
            )}

            <form onSubmit={handlePasswordSubmit} className="flex flex-col gap-4">
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="email" className="text-[12px] font-medium">Email</Label>
                <Input
                  id="email"
                  type="email"
                  autoComplete="email"
                  required
                  value={email}
                  onChange={(e) => { setEmail(e.target.value); if (error) clearError() }}
                  placeholder="you@example.com"
                />
              </div>

              <div className="flex flex-col gap-1.5">
                <Label htmlFor="password" className="text-[12px] font-medium">Password</Label>
                <Input
                  id="password"
                  type="password"
                  autoComplete="current-password"
                  required
                  value={password}
                  onChange={(e) => { setPassword(e.target.value); if (error) clearError() }}
                  placeholder="••••••••"
                />
              </div>

              {errorBox}

              <Button type="submit" disabled={isLoading} className="mt-1">
                {isLoading ? 'Signing in…' : 'Sign in'}
              </Button>
            </form>
          </>
        )}
      </div>

      <p className="mt-6 flex flex-wrap items-center justify-center gap-x-4 gap-y-1 text-[11px] text-muted-foreground">
        <a href={MXTAC_REPO_URL} target="_blank" rel="noopener noreferrer" className="transition-colors hover:text-foreground">
          Source on GitHub
        </a>
        <a
          href={KYRA_MDR_URL}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-1 transition-colors hover:text-foreground"
        >
          Managed 24/7 monitoring: KYRA MDR
          <ExternalLink className="h-3 w-3" />
        </a>
      </p>
    </div>
  )
}
