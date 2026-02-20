import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { TopBar } from '../../layout/TopBar'
import { apiClient, auditLogsApi, authApi } from '../../../lib/api'
import type { AuditLogEntry } from '../../../types/api'

interface User {
  id: string
  email: string
  full_name: string | null
  role: string
  is_active: boolean
  mfa_enabled: boolean
}

/** Convert an OpenSearch-style range string (e.g. "now-7d") to an ISO 8601 datetime. */
function fromTsForRange(range: string): string {
  const now = new Date()
  const match = range.match(/^now-(\d+)([hd])$/)
  if (!match) return new Date(0).toISOString()
  const [, num, unit] = match
  const ms = unit === 'h'
    ? parseInt(num) * 3_600_000
    : parseInt(num) * 86_400_000
  return new Date(now.getTime() - ms).toISOString()
}

const ROLE_COLORS: Record<string, string> = {
  admin:    'text-crit-text bg-crit-bg',
  engineer: 'text-high-text bg-high-bg',
  hunter:   'text-blue bg-blue-light',
  analyst:  'text-text-primary bg-page',
  viewer:   'text-text-muted bg-page',
}

const ACTION_COLORS: Record<string, string> = {
  create: 'text-status-ok bg-status-ok/10',
  update: 'text-blue bg-blue-light',
  delete: 'text-crit-text bg-crit-bg',
  login:  'text-text-muted bg-page',
  logout: 'text-text-muted bg-page',
}

const ROLES = ['viewer', 'analyst', 'hunter', 'engineer', 'admin']

const PAGE_SIZE = 50

async function fetchUsers(): Promise<User[]> {
  return apiClient.get('/users').then(r => r.data)
}

export function AdminPage() {
  const queryClient = useQueryClient()
  const [activeTab, setActiveTab] = useState<'users' | 'audit'>('users')

  // Users tab state
  const { data: users = [], isLoading } = useQuery({ queryKey: ['users'], queryFn: fetchUsers })

  // Audit tab state
  const [auditPage, setAuditPage] = useState(1)
  const [timeRange, setTimeRange] = useState('now-7d')
  const [auditActorFilter, setAuditActorFilter] = useState('')
  const [auditActionFilter, setAuditActionFilter] = useState('')
  const [auditResourceFilter, setAuditResourceFilter] = useState('')

  const { data: auditLog, isLoading: auditLoading } = useQuery({
    queryKey: ['audit-log', auditPage, timeRange, auditActorFilter, auditActionFilter, auditResourceFilter],
    queryFn: () => auditLogsApi.list({
      page: auditPage,
      page_size: PAGE_SIZE,
      from_ts: fromTsForRange(timeRange),
      ...(auditActorFilter    ? { actor: auditActorFilter }            : {}),
      ...(auditActionFilter   ? { action: auditActionFilter }          : {}),
      ...(auditResourceFilter ? { resource_type: auditResourceFilter } : {}),
    }),
    enabled: activeTab === 'audit',
  })

  const updateRole = useMutation({
    mutationFn: ({ id, role }: { id: string; role: string }) =>
      apiClient.patch(`/users/${id}`, { role }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['users'] }),
  })

  const toggleActive = useMutation({
    mutationFn: ({ id, is_active }: { id: string; is_active: boolean }) =>
      apiClient.patch(`/users/${id}`, { is_active }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['users'] }),
  })

  const disableMfa = useMutation({
    mutationFn: (userId: string) => authApi.mfaDisable(userId),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['users'] }),
  })

  return (
    <>
      <TopBar crumb="Admin" />
      <div className="pt-[46px] px-5 pb-6">

        {/* Tabs */}
        <div className="flex gap-4 py-3 border-b border-border mb-4">
          {(['users', 'audit'] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`text-[12px] capitalize pb-2 border-b-2 transition-colors ${
                activeTab === tab
                  ? 'border-blue text-blue font-medium'
                  : 'border-transparent text-text-muted hover:text-text-secondary'
              }`}
            >
              {tab === 'users' ? 'Users & Roles' : 'Audit Log'}
            </button>
          ))}
        </div>

        {activeTab === 'users' && (
          <>
            <div className="flex items-center justify-between mb-3">
              <div className="text-[11px] text-text-muted">{users.length} users</div>
              <button className="h-[28px] px-4 bg-blue text-white text-[12px] rounded-md hover:opacity-90">
                + Invite User
              </button>
            </div>

            <div className="bg-surface rounded-md shadow-card overflow-hidden">
              {/* Header */}
              <div className="grid grid-cols-[1fr_150px_110px_70px_70px_80px] gap-2 px-4 py-2 border-b border-border">
                {['User', 'Email', 'Role', 'Status', 'MFA', 'Actions'].map((h) => (
                  <span key={h} className="text-[10px] font-medium text-text-muted uppercase">{h}</span>
                ))}
              </div>

              {isLoading && (
                <div className="flex items-center justify-center h-24 text-text-muted text-sm">Loading…</div>
              )}

              {users.map((user) => (
                <div key={user.id} className="grid grid-cols-[1fr_150px_110px_70px_70px_80px] gap-2 px-4 py-[7px] border-b border-section items-center">
                  <div>
                    <div className="text-[11px] text-text-primary font-medium">
                      {user.full_name || user.email.split('@')[0]}
                    </div>
                    <div className="text-[10px] text-text-muted">{user.id}</div>
                  </div>
                  <span className="text-[11px] text-text-muted truncate">{user.email}</span>
                  <select
                    value={user.role}
                    onChange={(e) => updateRole.mutate({ id: user.id, role: e.target.value })}
                    className={`text-[10px] font-medium px-2 py-[2px] rounded border-0 w-fit cursor-pointer focus:outline-none ${ROLE_COLORS[user.role] ?? ''}`}
                  >
                    {ROLES.map((r) => (
                      <option key={r} value={r} className="text-text-primary bg-surface capitalize">{r}</option>
                    ))}
                  </select>
                  <div className="flex items-center gap-1">
                    <span className={`w-[6px] h-[6px] rounded-full ${user.is_active ? 'bg-status-ok' : 'bg-border'}`} />
                    <span className="text-[10px] text-text-muted">{user.is_active ? 'Active' : 'Inactive'}</span>
                  </div>
                  <div className="flex items-center">
                    {user.mfa_enabled ? (
                      <span className="text-[10px] font-medium px-1.5 py-[2px] rounded bg-status-ok/10 text-status-ok">
                        On
                      </span>
                    ) : (
                      <span className="text-[10px] text-text-muted">—</span>
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => toggleActive.mutate({ id: user.id, is_active: !user.is_active })}
                      className="text-[10px] text-text-muted hover:text-text-secondary"
                    >
                      {user.is_active ? 'Disable' : 'Enable'}
                    </button>
                    {user.mfa_enabled && (
                      <button
                        onClick={() => {
                          if (confirm(`Disable MFA for ${user.email}?`)) {
                            disableMfa.mutate(user.id)
                          }
                        }}
                        disabled={disableMfa.isPending}
                        className="text-[10px] text-crit-text hover:opacity-70 disabled:opacity-40"
                        title="Disable MFA"
                      >
                        MFA↓
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>

            {/* Role descriptions */}
            <div className="mt-4 bg-surface rounded-md shadow-card p-4">
              <h3 className="text-[12px] font-semibold text-text-primary mb-3">Role Permissions</h3>
              <div className="grid grid-cols-5 gap-3">
                {[
                  { role: 'viewer',   desc: 'Read-only access to dashboards and alerts' },
                  { role: 'analyst',  desc: 'View + investigate + resolve alerts' },
                  { role: 'hunter',   desc: 'Analyst + query events + saved hunts' },
                  { role: 'engineer', desc: 'Hunter + manage rules + connectors' },
                  { role: 'admin',    desc: 'Full access including user management' },
                ].map(({ role, desc }) => (
                  <div key={role} className="p-3 bg-page rounded-md border border-border">
                    <div className={`text-[10px] font-medium px-2 py-[2px] rounded capitalize w-fit mb-2 ${ROLE_COLORS[role]}`}>
                      {role}
                    </div>
                    <div className="text-[10px] text-text-muted">{desc}</div>
                  </div>
                ))}
              </div>
            </div>
          </>
        )}

        {activeTab === 'audit' && (
          <div>
            {/* Filter bar */}
            <div className="flex items-center gap-2 mb-3 flex-wrap">
              <input
                value={auditActorFilter}
                onChange={(e) => { setAuditActorFilter(e.target.value); setAuditPage(1) }}
                placeholder="Actor"
                className="h-[28px] px-2 text-[11px] bg-surface border border-border rounded-md text-text-primary placeholder-text-muted focus:outline-none focus:border-blue w-[140px]"
              />
              <input
                value={auditActionFilter}
                onChange={(e) => { setAuditActionFilter(e.target.value); setAuditPage(1) }}
                placeholder="Action"
                className="h-[28px] px-2 text-[11px] bg-surface border border-border rounded-md text-text-primary placeholder-text-muted focus:outline-none focus:border-blue w-[110px]"
              />
              <input
                value={auditResourceFilter}
                onChange={(e) => { setAuditResourceFilter(e.target.value); setAuditPage(1) }}
                placeholder="Resource type"
                className="h-[28px] px-2 text-[11px] bg-surface border border-border rounded-md text-text-primary placeholder-text-muted focus:outline-none focus:border-blue w-[130px]"
              />
              <select
                value={timeRange}
                onChange={(e) => { setTimeRange(e.target.value); setAuditPage(1) }}
                className="h-[28px] px-2 text-[11px] bg-surface border border-border rounded-md text-text-primary focus:outline-none focus:border-blue"
              >
                <option value="now-1h">Last 1h</option>
                <option value="now-24h">Last 24h</option>
                <option value="now-7d">Last 7d</option>
                <option value="now-30d">Last 30d</option>
                <option value="now-90d">Last 90d</option>
              </select>
              <span className="ml-auto text-[10px] text-text-muted">
                {auditLog ? `${auditLog.pagination.total} entries` : ''}
              </span>
            </div>

            {/* Table */}
            <div className="bg-surface rounded-md shadow-card overflow-hidden">
              {/* Column headers */}
              <div className="grid grid-cols-[150px_1fr_80px_130px_1fr] gap-2 px-4 py-2 border-b border-border">
                {['Time', 'Actor', 'Action', 'Resource', 'Path'].map((h) => (
                  <span key={h} className="text-[10px] font-medium text-text-muted uppercase">{h}</span>
                ))}
              </div>

              {auditLoading && (
                <div className="flex items-center justify-center h-24 text-text-muted text-sm">Loading…</div>
              )}

              {!auditLoading && (auditLog?.items.length ?? 0) === 0 && (
                <div className="flex items-center justify-center h-24 text-[11px] text-text-muted">
                  No audit log entries found.
                </div>
              )}

              {auditLog?.items.map((entry: AuditLogEntry) => (
                <div
                  key={entry.id}
                  className="grid grid-cols-[150px_1fr_80px_130px_1fr] gap-2 px-4 py-[7px] border-b border-section items-center"
                >
                  <span className="text-[10px] text-text-muted font-mono">
                    {new Date(entry.timestamp).toLocaleString()}
                  </span>
                  <span className="text-[11px] text-text-primary truncate">{entry.actor}</span>
                  <span className={`text-[10px] font-medium px-2 py-[2px] rounded w-fit ${ACTION_COLORS[entry.action] ?? 'text-text-muted bg-page'}`}>
                    {entry.action}
                  </span>
                  <span className="text-[10px] text-text-muted truncate">
                    {entry.resource_type}{entry.resource_id ? ` / ${entry.resource_id.slice(0, 8)}` : ''}
                  </span>
                  <span className="text-[10px] text-text-muted font-mono truncate">
                    {[entry.request_method, entry.request_path].filter(Boolean).join(' ')}
                  </span>
                </div>
              ))}
            </div>

            {/* Pagination */}
            {auditLog && auditLog.pagination.total_pages > 1 && (
              <div className="flex items-center justify-between mt-3">
                <span className="text-[10px] text-text-muted">
                  Page {auditPage} of {auditLog.pagination.total_pages}
                </span>
                <div className="flex gap-2">
                  <button
                    onClick={() => setAuditPage(p => Math.max(1, p - 1))}
                    disabled={auditPage === 1}
                    className="h-[24px] px-3 text-[10px] bg-surface border border-border rounded text-text-muted hover:text-text-primary disabled:opacity-40"
                  >
                    Prev
                  </button>
                  <button
                    onClick={() => setAuditPage(p => p + 1)}
                    disabled={auditPage >= auditLog.pagination.total_pages}
                    className="h-[24px] px-3 text-[10px] bg-surface border border-border rounded text-text-muted hover:text-text-primary disabled:opacity-40"
                  >
                    Next
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </>
  )
}
