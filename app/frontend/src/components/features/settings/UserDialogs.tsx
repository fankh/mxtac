import { useState, type FormEvent } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Button } from '@/components/ui/button'
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { apiErrorMessage, usersApi } from '@/lib/api'
import { PASSWORD_POLICY_HINT, passwordProblem } from '@/lib/passwordPolicy'
import { useUIStore } from '@/stores/uiStore'
import type { User, UserRole } from '@/types/api'

const ROLES: { value: UserRole; label: string; description: string }[] = [
  { value: 'viewer', label: 'Viewer', description: 'Read detections and incidents' },
  { value: 'analyst', label: 'Analyst', description: 'Triage detections and incidents' },
  { value: 'hunter', label: 'Hunter', description: 'Analyst access plus event search and rule reading' },
  { value: 'engineer', label: 'Engineer', description: 'Hunter access plus rules and data sources' },
  { value: 'admin', label: 'Admin', description: 'Everything, including users' },
]

const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/

function RoleSelect({ value, onChange, disabled }: { value: UserRole; onChange: (r: UserRole) => void; disabled?: boolean }) {
  const current = ROLES.find((r) => r.value === value)
  return (
    <div className="space-y-1.5">
      <Label className="text-[12px] font-medium">Role</Label>
      <Select value={value} onValueChange={(v) => onChange(v as UserRole)} disabled={disabled}>
        <SelectTrigger aria-label="Role"><SelectValue /></SelectTrigger>
        <SelectContent>
          {ROLES.map((r) => <SelectItem key={r.value} value={r.value}>{r.label}</SelectItem>)}
        </SelectContent>
      </Select>
      {current && <p className="text-[11px] text-muted-foreground">{current.description}</p>}
    </div>
  )
}

function FormError({ message }: { message: string }) {
  if (!message) return null
  return <p role="alert" className="rounded-md border sev-critical px-3 py-2 text-[11px]">{message}</p>
}

// ── Add user (POST /users) ────────────────────────────────────────────────────

/** Create an account with a temporary password that the user must replace at first sign-in. Mount only while open. */
export function CreateUserDialog({ onClose }: { onClose: () => void }) {
  const queryClient = useQueryClient()
  const addNotification = useUIStore((s) => s.addNotification)
  const [email, setEmail] = useState('')
  const [fullName, setFullName] = useState('')
  const [role, setRole] = useState<UserRole>('analyst')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')

  const mutation = useMutation({
    mutationFn: () => usersApi.create({
      email: email.trim(),
      full_name: fullName.trim() || null,
      role,
      password,
    }),
    onSuccess: (user) => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      addNotification({ type: 'success', title: 'User added', message: user.email })
      onClose()
    },
    onError: (err: unknown) => {
      const message = apiErrorMessage(err, 'Could not add the user')
      setError(message)
      addNotification({ type: 'error', title: 'Add user failed', message })
    },
  })

  const submit = (e: FormEvent) => {
    e.preventDefault()
    if (!EMAIL_RE.test(email.trim())) return setError('Enter a valid email address')
    const problem = passwordProblem(password)
    if (problem) return setError(problem)
    setError('')
    mutation.mutate()
  }

  return (
    <Dialog open onOpenChange={(next) => { if (!next) onClose() }}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Add user</DialogTitle>
          <DialogDescription>
            Set a temporary password and give it to the user. They must change it at first sign-in.
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={submit} className="space-y-3" noValidate>
          <div className="space-y-1.5">
            <Label htmlFor="new-user-email" className="text-[12px] font-medium">Email</Label>
            <Input id="new-user-email" type="email" value={email} autoComplete="off" maxLength={254}
              onChange={(e) => { setEmail(e.target.value); setError('') }} />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="new-user-name" className="text-[12px] font-medium">Full name</Label>
            <Input id="new-user-name" value={fullName} autoComplete="off" maxLength={255}
              onChange={(e) => setFullName(e.target.value)} />
          </div>
          <RoleSelect value={role} onChange={setRole} />
          <div className="space-y-1.5">
            <Label htmlFor="new-user-password" className="text-[12px] font-medium">Temporary password</Label>
            <Input id="new-user-password" type="password" value={password} autoComplete="new-password" maxLength={128}
              onChange={(e) => { setPassword(e.target.value); setError('') }} />
            <p className="text-[11px] text-muted-foreground">{PASSWORD_POLICY_HINT}</p>
          </div>
          <FormError message={error} />
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose} disabled={mutation.isPending}>Cancel</Button>
            <Button type="submit" disabled={mutation.isPending}>{mutation.isPending ? 'Adding…' : 'Add user'}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

// ── Edit user (PATCH /users/{id}) ─────────────────────────────────────────────

interface EditUserDialogProps {
  user: User
  /** True when the row is the signed-in admin, who must not demote their own account. */
  isSelf: boolean
  onClose: () => void
}

/** Change the name and role of an account. Mount only while open. */
export function EditUserDialog({ user, isSelf, onClose }: EditUserDialogProps) {
  const queryClient = useQueryClient()
  const addNotification = useUIStore((s) => s.addNotification)
  const [fullName, setFullName] = useState(user.full_name ?? '')
  const [role, setRole] = useState<UserRole>(user.role)
  const [error, setError] = useState('')

  const mutation = useMutation({
    mutationFn: () => {
      const name = fullName.trim()
      // The backend ignores null fields, so only changed, non-empty values are sent.
      return usersApi.update(user.id, {
        ...(name && name !== (user.full_name ?? '') ? { full_name: name } : {}),
        ...(role !== user.role ? { role } : {}),
      })
    },
    onSuccess: (saved) => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      queryClient.invalidateQueries({ queryKey: ['auth-me'] })
      addNotification({ type: 'success', title: 'User updated', message: saved.email })
      onClose()
    },
    onError: (err: unknown) => {
      const message = apiErrorMessage(err, 'Could not update the user')
      setError(message)
      addNotification({ type: 'error', title: 'Update failed', message })
    },
  })

  return (
    <Dialog open onOpenChange={(next) => { if (!next) onClose() }}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Edit user</DialogTitle>
          <DialogDescription>{user.email}</DialogDescription>
        </DialogHeader>
        <form onSubmit={(e) => { e.preventDefault(); setError(''); mutation.mutate() }} className="space-y-3" noValidate>
          <div className="space-y-1.5">
            <Label htmlFor="edit-user-name" className="text-[12px] font-medium">Full name</Label>
            <Input id="edit-user-name" value={fullName} autoComplete="off" maxLength={255}
              onChange={(e) => setFullName(e.target.value)} />
          </div>
          <RoleSelect value={role} onChange={setRole} disabled={isSelf} />
          {isSelf && <p className="text-[11px] text-muted-foreground">You cannot change your own role.</p>}
          <FormError message={error} />
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose} disabled={mutation.isPending}>Cancel</Button>
            <Button type="submit" disabled={mutation.isPending}>{mutation.isPending ? 'Saving…' : 'Save changes'}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
