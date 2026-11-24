import { useState, type FormEvent, type ReactNode } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { KeyRound, RefreshCw, ShieldCheck } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { authApi } from '@/lib/api'
import { PASSWORD_POLICY_HINT, passwordErrorMessage, passwordProblem } from '@/lib/passwordPolicy'
import { cn } from '@/lib/utils'
import { useUIStore } from '@/stores/uiStore'
import { MfaSetupModal } from '../auth/MfaSetupModal'

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-4 py-2">
      <dt className="text-[11px] text-muted-foreground">{label}</dt>
      <dd className="text-[12px] text-foreground">{children}</dd>
    </div>
  )
}

/** Change the password of the signed-in account (POST /auth/password). */
function ChangePasswordCard() {
  const addNotification = useUIStore((s) => s.addNotification)
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState('')

  const mutation = useMutation({
    mutationFn: () => authApi.changePassword(current, next),
    onSuccess: () => {
      setCurrent('')
      setNext('')
      setConfirm('')
      setError('')
      addNotification({ type: 'success', title: 'Password changed', message: 'Use the new password the next time you sign in.' })
    },
    onError: (err: unknown) => {
      const message = passwordErrorMessage(err, 'Could not change the password')
      setError(message)
      addNotification({ type: 'error', title: 'Password change failed', message })
    },
  })

  const submit = (e: FormEvent) => {
    e.preventDefault()
    if (!current) return setError('Enter your current password')
    const problem = passwordProblem(next)
    if (problem) return setError(problem)
    if (next !== confirm) return setError('The new passwords do not match')
    if (next === current) return setError('The new password must differ from the current one')
    setError('')
    mutation.mutate()
  }

  const field = (id: string, label: string, value: string, onChange: (v: string) => void, autoComplete: string) => (
    <div className="space-y-1.5">
      <Label htmlFor={id} className="text-[12px] font-medium">{label}</Label>
      <Input id={id} type="password" value={value} autoComplete={autoComplete} maxLength={128}
        onChange={(e) => { onChange(e.target.value); setError('') }} />
    </div>
  )

  return (
    <Card className="md:col-span-2">
      <CardContent className="p-4">
        <h2 className="text-[12px] font-semibold text-foreground">Change password</h2>
        <form onSubmit={submit} className="mt-3 max-w-sm space-y-3" noValidate aria-label="Change password">
          {field('current-password', 'Current password', current, setCurrent, 'current-password')}
          {field('new-password', 'New password', next, setNext, 'new-password')}
          <p className="text-[11px] text-muted-foreground">
            {PASSWORD_POLICY_HINT} It cannot be one of your last 2 passwords.
          </p>
          {field('confirm-password', 'Confirm new password', confirm, setConfirm, 'new-password')}
          {error && <p role="alert" className="sev-critical rounded-md border px-3 py-2 text-[11px]">{error}</p>}
          <Button type="submit" className="gap-1.5" disabled={mutation.isPending}>
            <KeyRound className="h-3.5 w-3.5" />
            {mutation.isPending ? 'Changing…' : 'Change password'}
          </Button>
        </form>
      </CardContent>
    </Card>
  )
}

export function ProfileTab() {
  const [mfaOpen, setMfaOpen] = useState(false)
  // Same query key as MfaSetupModal, so finishing MFA setup refreshes this card.
  const { data: me, isLoading, isError, refetch } = useQuery({ queryKey: ['auth-me'], queryFn: authApi.me })

  if (isLoading) {
    return (
      <div className="grid max-w-4xl gap-4 md:grid-cols-2" aria-label="Loading profile">
        <Skeleton className="h-40 w-full rounded-lg" />
        <Skeleton className="h-40 w-full rounded-lg" />
      </div>
    )
  }

  if (isError || !me) {
    return (
      <Card className="max-w-2xl">
        <CardContent className="flex flex-col items-center gap-3 p-8 text-center">
          <p className="text-[12px] text-destructive">Could not load your profile.</p>
          <Button variant="outline" className="gap-1.5" onClick={() => refetch()}>
            <RefreshCw className="h-3.5 w-3.5" />
            Retry
          </Button>
        </CardContent>
      </Card>
    )
  }

  return (
    <div className="grid max-w-4xl gap-4 md:grid-cols-2">
      <Card>
        <CardContent className="p-4">
          <h2 className="text-[12px] font-semibold text-foreground">Profile</h2>
          <dl className="mt-2 divide-y divide-border">
            <Field label="Email">{me.email}</Field>
            <Field label="Full name">{me.full_name || '–'}</Field>
            <Field label="Role"><span className="capitalize">{me.role}</span></Field>
          </dl>
          <p className="mt-2 text-[11px] text-muted-foreground">An administrator can change your name and role.</p>
        </CardContent>
      </Card>

      <Card>
        <CardContent className="p-4">
          <h2 className="text-[12px] font-semibold text-foreground">Security</h2>
          <dl className="mt-2 divide-y divide-border">
            <Field label="Multi-factor authentication">
              <span className={cn('inline-flex rounded-full border px-2 py-0.5 text-[10px] font-medium', me.mfa_enabled ? 'status-green' : 'sev-medium')}>
                {me.mfa_enabled ? 'On' : 'Off'}
              </span>
            </Field>
          </dl>
          <p className="mt-2 text-[11px] text-muted-foreground">
            {me.mfa_enabled
              ? 'Sign-in asks for a code from your authenticator app. An administrator can reset it.'
              : 'Add a code from an authenticator app as a second step at sign-in.'}
          </p>
          <Button variant={me.mfa_enabled ? 'outline' : 'default'} className="mt-3 gap-1.5" onClick={() => setMfaOpen(true)}>
            <ShieldCheck className="h-3.5 w-3.5" />
            {me.mfa_enabled ? 'View MFA status' : 'Set up MFA'}
          </Button>
        </CardContent>
      </Card>

      <ChangePasswordCard />

      {mfaOpen && <MfaSetupModal onClose={() => setMfaOpen(false)} />}
    </div>
  )
}
