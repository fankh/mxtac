import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { TopBar } from '../../layout/TopBar'
import { apiClient } from '../../../lib/api'

interface User {
  id: string
  email: string
  full_name: string | null
  role: string
  is_active: boolean
}

interface AuditLogEntry {
  id: string
  timestamp: string
  actor: string
  action: string
  resource_type: string
  resource_id: string
  details: Record<string, unknown>
  request_ip: string | null
  request_method: string | null
  request_path: string | null
}

interface AuditLogResponse {
  total: number
  page: number
  page_size: number
  items: AuditLogEntry[]
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

async function fetchAuditLog(params: {
  page: number
  page_size: number
  actor?: string
  action?: string
  resource_type?: string
  time_from: string
}): Promise<AuditLogResponse> {
  return apiClient.get('/admin/audit-log', { params }).then(r => r.data)
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
    queryFn: () => fetchAuditLog({
      page: auditPage,
      page_size: PAGE_SIZE,
      time_from: timeRange,
      ...(auditActorFilter   ? { actor: auditActorFilter }           : {}),
      ...(auditActionFilter  ? { action: auditActionFilter }         : {}),
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
              <div className="grid grid-cols-[1fr_160px_120px_80px_60px] gap-2 px-4 py-2 border-b border-border">
                {['User', 'Email', 'Role', 'Status', 'Actions'].map((h) => (
                  <span key={h} className="text-[10px] font-medium text-text-muted uppercase">{h}</span>
                ))}
              </div>

              {isLoading && (
                <div className="flex items-center justify-center h-24 text-text-muted text-sm">Loading…</div>
              )}

              {users.map((user) => (
                <div key={user.id} className="grid grid-cols-[1fr_160px_120px_80px_60px] gap-2 px-4 py-[7px] border-b border-section items-center">
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
                  <button
                    onClick={() => toggleActive.mutate({ id: user.id, is_active: !user.is_active })}
                    className="text-[10px] text-text-muted hover:text-text-secondary"
                  >
                    {user.is_active ? 'Disable' : 'Enable'}
                  </button>
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
          <div className="bg-surface rounded-md shadow-card p-4">
            <p className="text-[11px] text-text-muted text-center py-8">
              Audit log coming soon — requires OpenSearch integration.
            </p>
          </div>
        )}
      </div>
    </>
  )
}
