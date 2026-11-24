import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Pencil, RefreshCw, Search, ShieldOff, UserCheck, UserPlus, UserX, Users, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { EmptyState } from '@/components/ui/empty-state'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { apiErrorMessage, authApi, usersApi } from '@/lib/api'
import { cn } from '@/lib/utils'
import { useAuthStore } from '@/stores/authStore'
import { useUIStore } from '@/stores/uiStore'
import type { User } from '@/types/api'
import { ConfirmDialog } from '@/components/shared/ConfirmDialog'
import { CreateUserDialog, EditUserDialog } from './UserDialogs'

type Confirm = { kind: 'deactivate' | 'reset-mfa'; user: User } | null

const pill = 'inline-flex rounded-full border px-2 py-0.5 text-[10px] font-medium'

/** Admin-only user management on /users. */
export function UsersTab() {
  const queryClient = useQueryClient()
  const addNotification = useUIStore((s) => s.addNotification)
  const myEmail = useAuthStore((s) => s.user?.email)

  const [search, setSearch] = useState('')
  const [createOpen, setCreateOpen] = useState(false)
  const [editTarget, setEditTarget] = useState<User | null>(null)
  const [confirm, setConfirm] = useState<Confirm>(null)

  const { data, isLoading, isError, refetch } = useQuery({ queryKey: ['users'], queryFn: usersApi.list })
  const users = useMemo(() => data ?? [], [data])

  const refresh = () => queryClient.invalidateQueries({ queryKey: ['users'] })
  const fail = (title: string, fallback: string) => (err: unknown) =>
    addNotification({ type: 'error', title, message: apiErrorMessage(err, fallback) })

  // DELETE /users/{id} is a soft delete on the server: the account stays with is_active=false.
  const deactivateMutation = useMutation({
    mutationFn: (user: User) => usersApi.delete(user.id),
    onSuccess: (_, user) => {
      refresh()
      setConfirm(null)
      addNotification({ type: 'success', title: 'User deactivated', message: user.email })
    },
    onError: fail('Deactivate failed', 'Could not deactivate the user'),
  })

  const reactivateMutation = useMutation({
    mutationFn: (user: User) => usersApi.update(user.id, { is_active: true }),
    onSuccess: (user) => {
      refresh()
      addNotification({ type: 'success', title: 'User reactivated', message: user.email })
    },
    onError: fail('Reactivate failed', 'Could not reactivate the user'),
  })

  const resetMfaMutation = useMutation({
    mutationFn: (user: User) => authApi.mfaDisable(user.id),
    onSuccess: (_, user) => {
      refresh()
      queryClient.invalidateQueries({ queryKey: ['auth-me'] })
      setConfirm(null)
      addNotification({ type: 'success', title: 'MFA reset', message: user.email })
    },
    onError: fail('MFA reset failed', 'Could not reset MFA for the user'),
  })

  const visible = useMemo(() => {
    const q = search.trim().toLowerCase()
    const rows = q
      ? users.filter((u) => u.email.toLowerCase().includes(q) || (u.full_name ?? '').toLowerCase().includes(q) || u.role.includes(q))
      : users
    return [...rows].sort((a, b) => a.email.localeCompare(b.email))
  }, [users, search])

  const confirmPending = deactivateMutation.isPending || resetMfaMutation.isPending

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative w-full max-w-xs">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            className="h-8 pl-8 pr-8"
            placeholder="Search users"
            aria-label="Search users"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Escape') setSearch('') }}
          />
          {search && (
            <Button
              variant="ghost" size="icon" title="Clear search"
              className="absolute right-1 top-1/2 h-6 w-6 -translate-y-1/2"
              onClick={() => setSearch('')}
            >
              <X className="h-3.5 w-3.5" />
            </Button>
          )}
        </div>
        <Button className="ml-auto gap-1.5" onClick={() => setCreateOpen(true)}>
          <UserPlus className="h-3.5 w-3.5" />
          Add user
        </Button>
      </div>

      <Card>
        <CardContent className="p-0">
          {isLoading && (
            <div className="space-y-2 p-4" aria-label="Loading users">
              {[0, 1, 2].map((i) => <Skeleton key={i} className="h-8 w-full" />)}
            </div>
          )}

          {isError && (
            <div className="flex flex-col items-center gap-3 p-8 text-center">
              <p className="text-[12px] text-destructive">Could not load users.</p>
              <Button variant="outline" className="gap-1.5" onClick={() => refetch()}>
                <RefreshCw className="h-3.5 w-3.5" />
                Retry
              </Button>
            </div>
          )}

          {!isLoading && !isError && visible.length === 0 && (
            <EmptyState
              icon={Users}
              title={users.length === 0 ? 'No users' : 'No users match'}
              description={users.length === 0 ? 'Add the first user.' : 'Change the search text.'}
            />
          )}

          {!isLoading && !isError && visible.length > 0 && (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>User</TableHead>
                  <TableHead>Role</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>MFA</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {visible.map((u) => {
                  const isSelf = u.email === myEmail
                  return (
                    <TableRow key={u.id} className={cn(!u.is_active && 'opacity-60')}>
                      <TableCell className="text-[12px]">
                        <p className="font-medium text-foreground">
                          {u.full_name || u.email}
                          {isSelf && <span className="ml-1.5 text-[11px] font-normal text-muted-foreground">(you)</span>}
                        </p>
                        {u.full_name && <p className="text-[11px] text-muted-foreground">{u.email}</p>}
                      </TableCell>
                      <TableCell className="text-[12px] capitalize">{u.role}</TableCell>
                      <TableCell className="text-[12px]">
                        <span className={cn(pill, u.is_active ? 'status-green' : 'sev-info')}>
                          {u.is_active ? 'Active' : 'Inactive'}
                        </span>
                        {u.is_active && u.must_change_password && (
                          <span className={cn(pill, 'sev-medium ml-1')} title="Must set a new password at the next sign-in">Password pending</span>
                        )}
                      </TableCell>
                      <TableCell className="text-[12px] text-muted-foreground">{u.mfa_enabled ? 'On' : 'Off'}</TableCell>
                      <TableCell>
                        <div className="flex items-center justify-end gap-0.5">
                          <Button variant="ghost" size="icon" title={`Edit ${u.email}`} onClick={() => setEditTarget(u)}>
                            <Pencil className="h-3.5 w-3.5" />
                          </Button>
                          {u.mfa_enabled && (
                            <Button
                              variant="ghost" size="icon" title={`Reset MFA for ${u.email}`}
                              onClick={() => setConfirm({ kind: 'reset-mfa', user: u })}
                            >
                              <ShieldOff className="h-3.5 w-3.5" />
                            </Button>
                          )}
                          {u.is_active ? (
                            <Button
                              variant="ghost" size="icon"
                              title={isSelf ? 'You cannot deactivate your own account' : `Deactivate ${u.email}`}
                              className="hover:text-destructive"
                              disabled={isSelf}
                              onClick={() => setConfirm({ kind: 'deactivate', user: u })}
                            >
                              <UserX className="h-3.5 w-3.5" />
                            </Button>
                          ) : (
                            <Button
                              variant="ghost" size="icon" title={`Reactivate ${u.email}`}
                              disabled={reactivateMutation.isPending}
                              onClick={() => reactivateMutation.mutate(u)}
                            >
                              <UserCheck className="h-3.5 w-3.5" />
                            </Button>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {createOpen && <CreateUserDialog onClose={() => setCreateOpen(false)} />}
      {editTarget && (
        <EditUserDialog user={editTarget} isSelf={editTarget.email === myEmail} onClose={() => setEditTarget(null)} />
      )}

      <ConfirmDialog
        open={confirm !== null}
        title={confirm?.kind === 'reset-mfa' ? 'Reset MFA' : 'Deactivate user'}
        description={confirm?.kind === 'reset-mfa'
          ? `${confirm.user.email} will sign in with a password only until MFA is set up again.`
          : `${confirm?.user.email ?? 'This user'} will no longer be able to sign in. The account is kept and can be reactivated.`}
        confirmLabel={confirm?.kind === 'reset-mfa' ? 'Reset MFA' : 'Deactivate'}
        pendingLabel="Working…"
        pending={confirmPending}
        onConfirm={() => {
          if (!confirm) return
          if (confirm.kind === 'reset-mfa') resetMfaMutation.mutate(confirm.user)
          else deactivateMutation.mutate(confirm.user)
        }}
        onCancel={() => setConfirm(null)}
      />
    </div>
  )
}
