import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { TopBar } from '../../layout/TopBar'
import { useAuthStore } from '../../../stores/authStore'

type Tab = 'users' | 'system' | 'auth'

interface User {
  id: string
  email: string
  full_name: string | null
  role: string
  is_active: boolean
  mfa_enabled: boolean
  last_login_at: string | null
  created_at: string
}

interface SystemConfig {
  opensearch_host: string
  opensearch_port: number
  valkey_host: string
  syslog_enabled: boolean
  syslog_port: number
  debug: boolean
}

const ROLES = ['viewer', 'analyst', 'hunter', 'engineer', 'admin']

export function SettingsPage() {
  const queryClient = useQueryClient()
  const currentUser = useAuthStore(s => s.user)
  const [tab, setTab] = useState<Tab>('users')
  const hasToken = !!localStorage.getItem('access_token')

  // --- Users ---
  const { data: users, isLoading: usersLoading } = useQuery({
    queryKey: ['admin-users'],
    queryFn: async () => {
      const token = localStorage.getItem('access_token')
      const resp = await fetch('/api/v1/users', { headers: { Authorization: `Bearer ${token}` } })
      if (!resp.ok) return []
      const data = await resp.json()
      return (Array.isArray(data) ? data : data.items ?? data.content ?? []) as User[]
    },
    enabled: hasToken && tab === 'users',
    staleTime: 30_000,
  })

  // --- Create User ---
  const [showCreateUser, setShowCreateUser] = useState(false)
  const [newUser, setNewUser] = useState({ email: '', full_name: '', password: '', role: 'analyst' })

  const createUserMut = useMutation({
    mutationFn: async () => {
      const token = localStorage.getItem('access_token')
      const resp = await fetch('/api/v1/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify(newUser),
      })
      if (!resp.ok) throw new Error((await resp.json()).detail || 'Failed')
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin-users'] })
      setShowCreateUser(false)
      setNewUser({ email: '', full_name: '', password: '', role: 'analyst' })
    },
  })

  // --- System Config ---
  const [config, setConfig] = useState<SystemConfig>({
    opensearch_host: 'opensearch',
    opensearch_port: 9200,
    valkey_host: 'redis',
    syslog_enabled: false,
    syslog_port: 514,
    debug: false,
  })

  useEffect(() => {
    if (tab === 'system' && hasToken) {
      fetch('/api/v1/admin/config', { headers: { Authorization: `Bearer ${localStorage.getItem('access_token')}` } })
        .then(r => r.ok ? r.json() : null)
        .then(d => { if (d) setConfig(prev => ({ ...prev, ...d })) })
        .catch(() => {})
    }
  }, [tab, hasToken])

  const TABS: { key: Tab; label: string }[] = [
    { key: 'users', label: 'Users' },
    { key: 'system', label: 'System' },
    { key: 'auth', label: 'Authentication' },
  ]

  return (
    <>
      <TopBar crumb="Settings" />
      <div className="pt-[46px] px-5 pb-6">

        {/* Tab bar — matches Hunt/NDR search row position */}
        <div className="flex items-center gap-2 py-3">
          <div className="flex items-center border border-border rounded-md overflow-hidden">
            {TABS.map(t => (
              <button
                key={t.key}
                onClick={() => setTab(t.key)}
                className={`px-3 h-[32px] text-[11px] font-medium border-r border-border last:border-r-0 transition-colors ${
                  tab === t.key ? 'bg-blue text-white' : 'bg-surface text-text-secondary hover:bg-page'
                }`}
              >
                {t.label}
              </button>
            ))}
          </div>
        </div>

        {/* ── Users Tab ── */}
        {tab === 'users' && (
          <div>
            <div className="flex items-center justify-between mb-3">
              <span className="text-[11px] text-text-muted">
                <strong className="text-text-primary">{users?.length ?? 0}</strong> users
              </span>
              <button
                onClick={() => setShowCreateUser(true)}
                className="h-[26px] px-3 text-[11px] font-medium bg-blue text-white rounded-md hover:opacity-90 transition-opacity"
              >
                + Add User
              </button>
            </div>

            {usersLoading ? (
              <div className="flex items-center justify-center h-32 text-[11px] text-text-muted">Loading users…</div>
            ) : !users || users.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-48">
                <span className="text-text-muted text-2xl mb-3">⌕</span>
                <p className="text-[13px] font-semibold text-text-primary mb-1">No Users</p>
                <p className="text-[11px] text-text-muted">Add your first team member to get started.</p>
              </div>
            ) : (
              <div className="bg-surface border border-border rounded-lg overflow-hidden">
                <table className="w-full text-[11px]">
                  <thead>
                    <tr className="border-b border-border text-[11px] font-medium text-text-muted">
                      <th className="text-left p-2">Email</th>
                      <th className="text-left p-2">Name</th>
                      <th className="text-left p-2 w-[90px]">Role</th>
                      <th className="text-left p-2 w-[60px]">MFA</th>
                      <th className="text-left p-2 w-[60px]">Status</th>
                      <th className="text-left p-2 w-[100px]">Last Login</th>
                    </tr>
                  </thead>
                  <tbody>
                    {users.map(u => (
                      <tr key={u.id} className="border-b border-border/50 hover:bg-hover/50 transition-colors">
                        <td className="p-2 font-mono">{u.email}</td>
                        <td className="p-2 text-text-muted">{u.full_name || '—'}</td>
                        <td className="p-2">
                          <span className={`px-1.5 py-0.5 text-[9px] font-bold rounded border ${
                            u.role === 'admin' ? 'bg-purple-500/10 text-purple-600 border-purple-500/20' :
                            u.role === 'hunter' ? 'bg-orange-500/10 text-orange-600 border-orange-500/20' :
                            u.role === 'analyst' ? 'bg-blue-500/10 text-blue-600 border-blue-500/20' :
                            'bg-section text-text-muted border-border'
                          }`}>{u.role}</span>
                        </td>
                        <td className="p-2">
                          <span className={`text-[10px] ${u.mfa_enabled ? 'text-status-ok' : 'text-text-muted'}`}>
                            {u.mfa_enabled ? '✓ On' : 'Off'}
                          </span>
                        </td>
                        <td className="p-2">
                          <span className={`text-[10px] ${u.is_active ? 'text-status-ok' : 'text-crit-text'}`}>
                            {u.is_active ? 'Active' : 'Locked'}
                          </span>
                        </td>
                        <td className="p-2 text-[10px] text-text-muted">
                          {u.last_login_at ? new Date(u.last_login_at).toLocaleDateString() : 'Never'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* Create User Modal */}
            {showCreateUser && (
              <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center" onClick={() => setShowCreateUser(false)}>
                <div className="bg-surface border border-border rounded-lg p-6 w-[420px]" onClick={e => e.stopPropagation()}>
                  <h3 className="text-[12px] font-bold mb-4">Add User</h3>
                  <div className="space-y-3">
                    <div>
                      <label className="text-[11px] font-medium text-text-muted">Email<span className="text-crit-text ml-0.5">*</span></label>
                      <input type="email" value={newUser.email} onChange={e => setNewUser(p => ({ ...p, email: e.target.value }))}
                        placeholder="user@company.com" autoComplete="off"
                        className="w-full mt-1 h-[32px] pl-3 pr-3 text-[12px] border border-border rounded-md bg-surface text-text-primary focus:outline-none focus:border-blue" />
                    </div>
                    <div>
                      <label className="text-[11px] font-medium text-text-muted">Full Name</label>
                      <input type="text" value={newUser.full_name} onChange={e => setNewUser(p => ({ ...p, full_name: e.target.value }))}
                        placeholder="Jane Doe" autoComplete="off"
                        className="w-full mt-1 h-[32px] pl-3 pr-3 text-[12px] border border-border rounded-md bg-surface text-text-primary focus:outline-none focus:border-blue" />
                    </div>
                    <div>
                      <label className="text-[11px] font-medium text-text-muted">Password<span className="text-crit-text ml-0.5">*</span></label>
                      <input type="password" value={newUser.password} onChange={e => setNewUser(p => ({ ...p, password: e.target.value }))}
                        placeholder="Min 8 characters" autoComplete="off"
                        className="w-full mt-1 h-[32px] pl-3 pr-3 text-[12px] border border-border rounded-md bg-surface text-text-primary focus:outline-none focus:border-blue" />
                    </div>
                    <div>
                      <label className="text-[11px] font-medium text-text-muted">Role</label>
                      <div className="flex items-center border border-border rounded-md overflow-hidden mt-1">
                        {ROLES.map(r => (
                          <button key={r} onClick={() => setNewUser(p => ({ ...p, role: r }))}
                            className={`flex-1 h-[32px] text-[10px] font-medium border-r border-border last:border-r-0 transition-colors capitalize ${
                              newUser.role === r ? 'bg-blue text-white' : 'bg-surface text-text-secondary hover:bg-page'
                            }`}>
                            {r}
                          </button>
                        ))}
                      </div>
                    </div>
                    {createUserMut.isError && (
                      <p className="text-[11px] text-crit-text">{(createUserMut.error as Error).message}</p>
                    )}
                  </div>
                  <div className="flex justify-end gap-2 mt-4">
                    <button onClick={() => setShowCreateUser(false)} className="h-[32px] px-3 text-[12px] border border-border rounded-md hover:bg-hover transition-colors">Cancel</button>
                    <button onClick={() => createUserMut.mutate()} disabled={createUserMut.isPending || !newUser.email || !newUser.password}
                      className="h-[32px] px-4 text-[12px] font-medium bg-blue text-white rounded-md hover:opacity-90 transition-opacity disabled:opacity-50">
                      {createUserMut.isPending ? 'Creating…' : 'Create User'}
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── System Tab ── */}
        {tab === 'system' && (
          <div>
            <div className="text-[11px] text-text-muted mb-3">
              <strong className="text-text-primary">System Configuration</strong> — infrastructure connection settings
            </div>

            <div className="space-y-4">
              {/* OpenSearch */}
              <div className="bg-surface border border-border rounded-lg p-4">
                <h3 className="text-[11px] font-semibold mb-3">OpenSearch</h3>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="text-[11px] font-medium text-text-muted">Host</label>
                    <input type="text" value={config.opensearch_host} onChange={e => setConfig(p => ({ ...p, opensearch_host: e.target.value }))}
                      className="w-full mt-1 h-[32px] pl-3 text-[12px] border border-border rounded-md bg-surface text-text-primary focus:outline-none focus:border-blue" />
                  </div>
                  <div>
                    <label className="text-[11px] font-medium text-text-muted">Port</label>
                    <input type="number" value={config.opensearch_port} onChange={e => setConfig(p => ({ ...p, opensearch_port: Number(e.target.value) }))}
                      className="w-full mt-1 h-[32px] pl-3 text-[12px] border border-border rounded-md bg-surface text-text-primary focus:outline-none focus:border-blue" />
                  </div>
                </div>
              </div>

              {/* Valkey / Redis */}
              <div className="bg-surface border border-border rounded-lg p-4">
                <h3 className="text-[11px] font-semibold mb-3">Valkey (Cache & Queue)</h3>
                <div>
                  <label className="text-[11px] font-medium text-text-muted">Host</label>
                  <input type="text" value={config.valkey_host} onChange={e => setConfig(p => ({ ...p, valkey_host: e.target.value }))}
                    className="w-full mt-1 h-[32px] pl-3 text-[12px] border border-border rounded-md bg-surface text-text-primary focus:outline-none focus:border-blue" />
                </div>
              </div>

              {/* Syslog Receiver */}
              <div className="bg-surface border border-border rounded-lg p-4">
                <h3 className="text-[11px] font-semibold mb-3">Syslog Receiver</h3>
                <div className="grid grid-cols-2 gap-3">
                  <div className="flex items-center gap-2">
                    <button onClick={() => setConfig(p => ({ ...p, syslog_enabled: !p.syslog_enabled }))}
                      className={`w-8 h-[18px] rounded-full transition-colors ${config.syslog_enabled ? 'bg-status-ok' : 'bg-border'}`}>
                      <div className={`w-3.5 h-3.5 rounded-full bg-white shadow transition-transform ${config.syslog_enabled ? 'translate-x-4' : 'translate-x-0.5'}`} />
                    </button>
                    <span className="text-[11px]">{config.syslog_enabled ? 'Enabled' : 'Disabled'}</span>
                  </div>
                  <div>
                    <label className="text-[11px] font-medium text-text-muted">Port</label>
                    <input type="number" value={config.syslog_port} onChange={e => setConfig(p => ({ ...p, syslog_port: Number(e.target.value) }))}
                      disabled={!config.syslog_enabled}
                      className="w-full mt-1 h-[32px] pl-3 text-[12px] border border-border rounded-md bg-surface text-text-primary focus:outline-none focus:border-blue disabled:opacity-50" />
                  </div>
                </div>
              </div>

              {/* Debug Mode */}
              <div className="bg-surface border border-border rounded-lg p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-[11px] font-semibold">Debug Mode</h3>
                    <p className="text-[10px] text-text-muted mt-0.5">Enable verbose logging and SQL query output</p>
                  </div>
                  <button onClick={() => setConfig(p => ({ ...p, debug: !p.debug }))}
                    className={`w-8 h-[18px] rounded-full transition-colors ${config.debug ? 'bg-high-text' : 'bg-border'}`}>
                    <div className={`w-3.5 h-3.5 rounded-full bg-white shadow transition-transform ${config.debug ? 'translate-x-4' : 'translate-x-0.5'}`} />
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ── Authentication Tab ── */}
        {tab === 'auth' && (
          <div>
            <div className="text-[11px] text-text-muted mb-3">
              <strong className="text-text-primary">Authentication Settings</strong> — security policies for user access
            </div>

            <div className="space-y-4">
              {/* Password Policy */}
              <div className="bg-surface border border-border rounded-lg p-4">
                <h3 className="text-[11px] font-semibold mb-3">Password Policy</h3>
                <div className="space-y-2">
                  {[
                    { label: 'Minimum length', value: '8 characters', key: 'min_length' },
                    { label: 'Require uppercase', value: 'Yes', key: 'uppercase' },
                    { label: 'Require number', value: 'Yes', key: 'number' },
                    { label: 'Require special character', value: 'Yes', key: 'special' },
                    { label: 'Password expiry', value: '90 days', key: 'expiry' },
                    { label: 'History (no reuse)', value: 'Last 2 passwords', key: 'history' },
                  ].map(rule => (
                    <div key={rule.key} className="flex items-center justify-between text-[11px]">
                      <span className="text-text-muted">{rule.label}</span>
                      <span className="text-text-primary font-medium">{rule.value}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Session Policy */}
              <div className="bg-surface border border-border rounded-lg p-4">
                <h3 className="text-[11px] font-semibold mb-3">Session Policy</h3>
                <div className="space-y-2">
                  {[
                    { label: 'Access token lifetime', value: '60 minutes' },
                    { label: 'Refresh token lifetime', value: '7 days' },
                    { label: 'Account lockout after', value: '5 failed attempts' },
                    { label: 'Inactivity lock', value: '90 days' },
                  ].map(rule => (
                    <div key={rule.label} className="flex items-center justify-between text-[11px]">
                      <span className="text-text-muted">{rule.label}</span>
                      <span className="text-text-primary font-medium">{rule.value}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* MFA */}
              <div className="bg-surface border border-border rounded-lg p-4">
                <h3 className="text-[11px] font-semibold mb-3">Multi-Factor Authentication</h3>
                <div className="space-y-2">
                  {[
                    { label: 'MFA method', value: 'TOTP (Authenticator app)' },
                    { label: 'Backup codes', value: '8 codes, 10 chars each' },
                    { label: 'Max MFA attempts', value: '3 per token' },
                    { label: 'Enforce MFA for admins', value: 'Recommended' },
                  ].map(rule => (
                    <div key={rule.label} className="flex items-center justify-between text-[11px]">
                      <span className="text-text-muted">{rule.label}</span>
                      <span className="text-text-primary font-medium">{rule.value}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </>
  )
}
