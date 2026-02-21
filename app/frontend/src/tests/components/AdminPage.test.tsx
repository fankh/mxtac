// vi.mock is hoisted before imports — declare all module mocks first.

vi.mock('../../lib/api', () => ({
  apiClient: {
    get:   vi.fn(),
    patch: vi.fn(),
  },
  auditLogsApi: {
    list: vi.fn(),
    get:  vi.fn(),
  },
  authApi: {
    mfaDisable: vi.fn(),
  },
}))

vi.mock('../../components/layout/TopBar', () => ({
  TopBar: ({ crumb }: { crumb: string }) => (
    <header data-testid="topbar">{crumb}</header>
  ),
}))

import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AdminPage } from '../../components/features/admin/AdminPage'
import { apiClient, auditLogsApi, authApi } from '../../lib/api'

// ---------------------------------------------------------------------------
// Typed references to the mocked APIs
// ---------------------------------------------------------------------------

const mockGet        = apiClient.get       as ReturnType<typeof vi.fn>
const mockPatch      = apiClient.patch     as ReturnType<typeof vi.fn>
const mockAudit      = auditLogsApi.list   as ReturnType<typeof vi.fn>
const mockMfaDisable = authApi.mfaDisable  as ReturnType<typeof vi.fn>

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

const makeUser = (overrides: Record<string, unknown> = {}) => ({
  id:        'user-001',
  email:     'admin@mxtac.local',
  full_name: 'System Admin',
  role:      'admin',
  is_active: true,
  ...overrides,
})

const makeAuditEntry = (overrides: Record<string, unknown> = {}) => ({
  id:             'audit-001',
  timestamp:      '2024-01-15T10:30:00.000Z',
  actor:          'admin@mxtac.local',
  action:         'create',
  resource_type:  'incident',
  resource_id:    'inc-abc123',
  details:        {},
  request_ip:     '127.0.0.1',
  request_method: 'POST',
  request_path:   '/api/v1/incidents',
  user_agent:     null,
  ...overrides,
})

/** Returns a PaginatedResponse<AuditLogEntry> matching the /audit-logs backend format. */
const makeAuditResponse = (
  items: unknown[] = [],
  paginationOverrides: Record<string, unknown> = {},
) => ({
  items,
  pagination: {
    page:        1,
    page_size:   50,
    total:       items.length,
    total_pages: 1,
    ...paginationOverrides,
  },
})

// ---------------------------------------------------------------------------
// Render helper
// ---------------------------------------------------------------------------

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry:     false,
        staleTime: Infinity,
      },
    },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <AdminPage />
    </QueryClientProvider>,
  )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('AdminPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    // Default: pending forever → loading state
    mockGet.mockReturnValue(new Promise<never>(() => {}))
    mockPatch.mockReturnValue(new Promise<never>(() => {}))
    mockAudit.mockReturnValue(new Promise<never>(() => {}))
  })

  // =========================================================================
  // TopBar
  // =========================================================================
  describe('TopBar', () => {
    it('renders the TopBar with the "Admin" crumb', () => {
      renderPage()
      expect(screen.getByTestId('topbar')).toHaveTextContent('Admin')
    })
  })

  // =========================================================================
  // Tab navigation — static rendering
  // =========================================================================
  describe('tab navigation', () => {
    it('renders the "Users & Roles" tab button', () => {
      renderPage()
      expect(screen.getByRole('button', { name: 'Users & Roles' })).toBeInTheDocument()
    })

    it('renders the "Audit Log" tab button', () => {
      renderPage()
      expect(screen.getByRole('button', { name: 'Audit Log' })).toBeInTheDocument()
    })

    it('"Users & Roles" tab is active by default', () => {
      renderPage()
      const usersTab = screen.getByRole('button', { name: 'Users & Roles' })
      expect(usersTab).toHaveClass('border-blue')
    })

    it('"Audit Log" tab is inactive by default', () => {
      renderPage()
      const auditTab = screen.getByRole('button', { name: 'Audit Log' })
      expect(auditTab).not.toHaveClass('border-blue')
    })

    it('clicking "Audit Log" switches to the audit tab', () => {
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Audit Log' }))
      expect(screen.getByText('Time')).toBeInTheDocument()
    })

    it('clicking "Audit Log" hides the users table', async () => {
      mockGet.mockResolvedValue({ data: [makeUser()] })
      renderPage()
      await waitFor(() => expect(screen.getByText('System Admin')).toBeInTheDocument())
      fireEvent.click(screen.getByRole('button', { name: 'Audit Log' }))
      expect(screen.queryByText('System Admin')).not.toBeInTheDocument()
    })

    it('clicking "Users & Roles" after switching back hides the audit table', () => {
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Audit Log' }))
      fireEvent.click(screen.getByRole('button', { name: 'Users & Roles' }))
      expect(screen.queryByText('Time')).not.toBeInTheDocument()
    })
  })

  // =========================================================================
  // Audit Log tab — column headers
  // =========================================================================
  describe('audit log tab — column headers', () => {
    it('shows audit log column headers on the audit tab', () => {
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Audit Log' }))
      expect(screen.getByText('Time')).toBeInTheDocument()
      expect(screen.getByText('Actor')).toBeInTheDocument()
      expect(screen.getByText('Action')).toBeInTheDocument()
      expect(screen.getByText('Resource')).toBeInTheDocument()
      expect(screen.getByText('Path')).toBeInTheDocument()
    })
  })

  // =========================================================================
  // Audit Log tab — loading state
  // =========================================================================
  describe('audit log tab — loading state', () => {
    it('shows "Loading…" on the audit tab while the query is pending', () => {
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Audit Log' }))
      expect(screen.getByText('Loading…')).toBeInTheDocument()
    })

    it('does not show audit entries while loading', () => {
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Audit Log' }))
      expect(screen.queryByText('admin@mxtac.local')).not.toBeInTheDocument()
    })

    it('does not show the empty-state message while loading', () => {
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Audit Log' }))
      expect(screen.queryByText('No audit log entries found.')).not.toBeInTheDocument()
    })
  })

  // =========================================================================
  // Audit Log tab — empty state
  // =========================================================================
  describe('audit log tab — empty state', () => {
    it('shows "No audit log entries found." when the response is empty', async () => {
      mockAudit.mockResolvedValue(makeAuditResponse([]))
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Audit Log' }))
      await waitFor(() =>
        expect(screen.getByText('No audit log entries found.')).toBeInTheDocument(),
      )
    })
  })

  // =========================================================================
  // Audit Log tab — success state
  // =========================================================================
  describe('audit log tab — success state', () => {
    it('renders an audit log entry row', async () => {
      mockAudit.mockResolvedValue(makeAuditResponse([makeAuditEntry()]))
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Audit Log' }))
      await waitFor(() => expect(screen.getByText('admin@mxtac.local')).toBeInTheDocument())
      expect(screen.getByText('create')).toBeInTheDocument()
      expect(screen.getByText('POST /api/v1/incidents')).toBeInTheDocument()
    })

    it('renders the resource_type in the row', async () => {
      mockAudit.mockResolvedValue(makeAuditResponse([makeAuditEntry()]))
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Audit Log' }))
      // resource column renders "{resource_type} / {resource_id[:8]}"
      await waitFor(() => expect(screen.getByText(/incident \/ inc-abc1/)).toBeInTheDocument())
    })

    it('renders multiple audit entries', async () => {
      mockAudit.mockResolvedValue(makeAuditResponse([
        makeAuditEntry({ id: '1', actor: 'alice@example.com', action: 'login' }),
        makeAuditEntry({ id: '2', actor: 'bob@example.com',   action: 'delete' }),
      ]))
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Audit Log' }))
      await waitFor(() => {
        expect(screen.getByText('alice@example.com')).toBeInTheDocument()
        expect(screen.getByText('bob@example.com')).toBeInTheDocument()
      })
    })

    it('does not show "Loading…" in success state', async () => {
      mockAudit.mockResolvedValue(makeAuditResponse([makeAuditEntry()]))
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Audit Log' }))
      await waitFor(() => expect(screen.queryByText('Loading…')).not.toBeInTheDocument())
    })
  })

  // =========================================================================
  // Audit Log tab — entry count
  // =========================================================================
  describe('audit log tab — entry count', () => {
    it('shows total entry count from pagination.total', async () => {
      mockAudit.mockResolvedValue(makeAuditResponse([makeAuditEntry()], { total: 73 }))
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Audit Log' }))
      await waitFor(() => expect(screen.getByText('73 entries')).toBeInTheDocument())
    })
  })

  // =========================================================================
  // Audit Log tab — filter bar
  // =========================================================================
  describe('audit log tab — filter bar', () => {
    it('shows filter inputs on the audit tab', () => {
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Audit Log' }))
      expect(screen.getByPlaceholderText('Actor')).toBeInTheDocument()
      expect(screen.getByPlaceholderText('Action')).toBeInTheDocument()
      expect(screen.getByPlaceholderText('Resource type')).toBeInTheDocument()
    })

    it('shows the time-range dropdown on the audit tab', () => {
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Audit Log' }))
      expect(screen.getByText('Last 7d')).toBeInTheDocument()
    })

    it('passes actor filter to auditLogsApi.list when typed', async () => {
      mockAudit.mockResolvedValue(makeAuditResponse())
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Audit Log' }))
      await waitFor(() => expect(mockAudit).toHaveBeenCalledTimes(1))
      fireEvent.change(screen.getByPlaceholderText('Actor'), { target: { value: 'admin@mxtac.local' } })
      await waitFor(() => {
        const lastCall = mockAudit.mock.calls.at(-1)![0]
        expect(lastCall.actor).toBe('admin@mxtac.local')
      })
    })

    it('passes action filter to auditLogsApi.list when typed', async () => {
      mockAudit.mockResolvedValue(makeAuditResponse())
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Audit Log' }))
      await waitFor(() => expect(mockAudit).toHaveBeenCalledTimes(1))
      fireEvent.change(screen.getByPlaceholderText('Action'), { target: { value: 'delete' } })
      await waitFor(() => {
        const lastCall = mockAudit.mock.calls.at(-1)![0]
        expect(lastCall.action).toBe('delete')
      })
    })

    it('passes resource_type filter to auditLogsApi.list when typed', async () => {
      mockAudit.mockResolvedValue(makeAuditResponse())
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Audit Log' }))
      await waitFor(() => expect(mockAudit).toHaveBeenCalledTimes(1))
      fireEvent.change(screen.getByPlaceholderText('Resource type'), { target: { value: 'user' } })
      await waitFor(() => {
        const lastCall = mockAudit.mock.calls.at(-1)![0]
        expect(lastCall.resource_type).toBe('user')
      })
    })

    it('passes an ISO 8601 from_ts (not OpenSearch date math) to auditLogsApi.list', async () => {
      mockAudit.mockResolvedValue(makeAuditResponse())
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Audit Log' }))
      await waitFor(() => expect(mockAudit).toHaveBeenCalledTimes(1))
      const firstCall = mockAudit.mock.calls[0][0]
      expect(firstCall.from_ts).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/)
    })

    it('does not pass actor when the actor input is empty', async () => {
      mockAudit.mockResolvedValue(makeAuditResponse())
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Audit Log' }))
      await waitFor(() => expect(mockAudit).toHaveBeenCalledTimes(1))
      expect(mockAudit.mock.calls[0][0].actor).toBeUndefined()
    })
  })

  // =========================================================================
  // Audit Log tab — API call lifecycle
  // =========================================================================
  describe('audit log tab — API call lifecycle', () => {
    it('does not call auditLogsApi.list on initial mount (users tab is default)', async () => {
      mockGet.mockResolvedValue({ data: [] })
      renderPage()
      await waitFor(() => expect(mockGet).toHaveBeenCalledTimes(1))
      expect(mockAudit).not.toHaveBeenCalled()
    })

    it('calls auditLogsApi.list when switching to the audit tab', async () => {
      mockGet.mockResolvedValue({ data: [] })
      mockAudit.mockResolvedValue(makeAuditResponse())
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Audit Log' }))
      await waitFor(() => expect(mockAudit).toHaveBeenCalledTimes(1))
    })
  })

  // =========================================================================
  // Audit Log tab — pagination
  // =========================================================================
  describe('audit log tab — pagination', () => {
    it('does not show pagination when total_pages is 1', async () => {
      mockAudit.mockResolvedValue(makeAuditResponse([makeAuditEntry()], { total_pages: 1 }))
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Audit Log' }))
      await waitFor(() => {
        expect(screen.queryByText('Prev')).not.toBeInTheDocument()
        expect(screen.queryByText('Next')).not.toBeInTheDocument()
      })
    })

    it('shows pagination controls when total_pages > 1', async () => {
      mockAudit.mockResolvedValue(makeAuditResponse([makeAuditEntry()], { total: 100, total_pages: 2 }))
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Audit Log' }))
      await waitFor(() => {
        expect(screen.getByText('Prev')).toBeInTheDocument()
        expect(screen.getByText('Next')).toBeInTheDocument()
      })
    })

    it('shows the current page and total pages', async () => {
      mockAudit.mockResolvedValue(makeAuditResponse([makeAuditEntry()], { total: 150, total_pages: 3 }))
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Audit Log' }))
      await waitFor(() => expect(screen.getByText('Page 1 of 3')).toBeInTheDocument())
    })

    it('Prev button is disabled on page 1', async () => {
      mockAudit.mockResolvedValue(makeAuditResponse([makeAuditEntry()], { total: 100, total_pages: 2 }))
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Audit Log' }))
      const prevBtn = await screen.findByText('Prev')
      expect(prevBtn.closest('button')).toBeDisabled()
    })

    it('Next button is not disabled on page 1 of 2', async () => {
      mockAudit.mockResolvedValue(makeAuditResponse([makeAuditEntry()], { total: 100, total_pages: 2 }))
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Audit Log' }))
      const nextBtn = await screen.findByText('Next')
      expect(nextBtn.closest('button')).not.toBeDisabled()
    })

    it('clicking Next requests page 2', async () => {
      mockAudit.mockResolvedValue(makeAuditResponse([makeAuditEntry()], { total: 100, total_pages: 2 }))
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Audit Log' }))
      await waitFor(() => expect(mockAudit).toHaveBeenCalledTimes(1))
      fireEvent.click(await screen.findByText('Next'))
      await waitFor(() => {
        const lastCall = mockAudit.mock.calls.at(-1)![0]
        expect(lastCall.page).toBe(2)
      })
    })
  })

  // =========================================================================
  // Loading state — users tab
  // =========================================================================
  describe('loading state', () => {
    it('shows "Loading…" while the users query is pending', () => {
      renderPage()
      expect(screen.getByText('Loading…')).toBeInTheDocument()
    })

    it('does not show user rows while loading', () => {
      renderPage()
      expect(screen.queryByText('System Admin')).not.toBeInTheDocument()
    })

    it('shows the users count as "0 users" while loading (empty default)', () => {
      renderPage()
      expect(screen.getByText('0 users')).toBeInTheDocument()
    })
  })

  // =========================================================================
  // Column headers — users tab
  // =========================================================================
  describe('column headers', () => {
    beforeEach(() => {
      mockGet.mockResolvedValue({ data: [] })
    })

    it('renders "User" column header', async () => {
      renderPage()
      await waitFor(() => expect(screen.getByText('User')).toBeInTheDocument())
    })

    it('renders "Email" column header', async () => {
      renderPage()
      await waitFor(() => expect(screen.getByText('Email')).toBeInTheDocument())
    })

    it('renders "Role" column header', async () => {
      renderPage()
      await waitFor(() => expect(screen.getByText('Role')).toBeInTheDocument())
    })

    it('renders "Status" column header', async () => {
      renderPage()
      await waitFor(() => expect(screen.getByText('Status')).toBeInTheDocument())
    })

    it('renders "Actions" column header', async () => {
      renderPage()
      await waitFor(() => expect(screen.getByText('Actions')).toBeInTheDocument())
    })
  })

  // =========================================================================
  // Invite User button
  // =========================================================================
  describe('invite user button', () => {
    beforeEach(() => {
      mockGet.mockResolvedValue({ data: [] })
    })

    it('renders the "+ Invite User" button', async () => {
      renderPage()
      await waitFor(() =>
        expect(screen.getByRole('button', { name: '+ Invite User' })).toBeInTheDocument(),
      )
    })
  })

  // =========================================================================
  // Success state — user count
  // =========================================================================
  describe('user count', () => {
    it('shows "0 users" when the list is empty', async () => {
      mockGet.mockResolvedValue({ data: [] })
      renderPage()
      await waitFor(() => expect(screen.getByText('0 users')).toBeInTheDocument())
    })

    it('shows "1 users" with one user', async () => {
      mockGet.mockResolvedValue({ data: [makeUser()] })
      renderPage()
      await waitFor(() => expect(screen.getByText('1 users')).toBeInTheDocument())
    })

    it('shows "3 users" with three users', async () => {
      mockGet.mockResolvedValue({
        data: [
          makeUser({ id: 'u1', email: 'a@x.com' }),
          makeUser({ id: 'u2', email: 'b@x.com' }),
          makeUser({ id: 'u3', email: 'c@x.com' }),
        ],
      })
      renderPage()
      await waitFor(() => expect(screen.getByText('3 users')).toBeInTheDocument())
    })
  })

  // =========================================================================
  // Success state — user row rendering
  // =========================================================================
  describe('user row rendering', () => {
    it('renders the user full_name when present', async () => {
      mockGet.mockResolvedValue({ data: [makeUser({ full_name: 'System Admin' })] })
      renderPage()
      await waitFor(() => expect(screen.getByText('System Admin')).toBeInTheDocument())
    })

    it('falls back to email prefix when full_name is null', async () => {
      mockGet.mockResolvedValue({
        data: [makeUser({ full_name: null, email: 'analyst@mxtac.local' })],
      })
      renderPage()
      await waitFor(() => expect(screen.getByText('analyst')).toBeInTheDocument())
    })

    it('renders the user email', async () => {
      mockGet.mockResolvedValue({ data: [makeUser({ email: 'admin@mxtac.local' })] })
      renderPage()
      await waitFor(() => expect(screen.getByText('admin@mxtac.local')).toBeInTheDocument())
    })

    it('renders the user id as a sub-label', async () => {
      mockGet.mockResolvedValue({ data: [makeUser({ id: 'user-001' })] })
      renderPage()
      await waitFor(() => expect(screen.getByText('user-001')).toBeInTheDocument())
    })

    it('renders "Active" status for active users', async () => {
      mockGet.mockResolvedValue({ data: [makeUser({ is_active: true })] })
      renderPage()
      await waitFor(() => expect(screen.getByText('Active')).toBeInTheDocument())
    })

    it('renders "Inactive" status for inactive users', async () => {
      mockGet.mockResolvedValue({ data: [makeUser({ is_active: false })] })
      renderPage()
      await waitFor(() => expect(screen.getByText('Inactive')).toBeInTheDocument())
    })

    it('renders "Disable" action button for active users', async () => {
      mockGet.mockResolvedValue({ data: [makeUser({ is_active: true })] })
      renderPage()
      await waitFor(() => expect(screen.getByRole('button', { name: 'Disable' })).toBeInTheDocument())
    })

    it('renders "Enable" action button for inactive users', async () => {
      mockGet.mockResolvedValue({ data: [makeUser({ is_active: false })] })
      renderPage()
      await waitFor(() => expect(screen.getByRole('button', { name: 'Enable' })).toBeInTheDocument())
    })

    it('renders multiple user rows', async () => {
      mockGet.mockResolvedValue({
        data: [
          makeUser({ id: 'u1', email: 'alice@x.com', full_name: 'Alice' }),
          makeUser({ id: 'u2', email: 'bob@x.com',   full_name: 'Bob' }),
        ],
      })
      renderPage()
      await waitFor(() => {
        expect(screen.getByText('Alice')).toBeInTheDocument()
        expect(screen.getByText('Bob')).toBeInTheDocument()
      })
    })

    it('does not show "Loading…" in success state', async () => {
      mockGet.mockResolvedValue({ data: [makeUser()] })
      renderPage()
      await waitFor(() => {
        expect(screen.queryByText('Loading…')).not.toBeInTheDocument()
      })
    })
  })

  // =========================================================================
  // Role dropdown
  // =========================================================================
  describe('role dropdown', () => {
    it('renders a select with the current user role as value', async () => {
      mockGet.mockResolvedValue({ data: [makeUser({ role: 'analyst' })] })
      renderPage()
      await waitFor(() => {
        const select = screen.getByRole('combobox') as HTMLSelectElement
        expect(select.value).toBe('analyst')
      })
    })

    it('lists all five role options', async () => {
      mockGet.mockResolvedValue({ data: [makeUser()] })
      renderPage()
      await waitFor(() => {
        const options = screen.getAllByRole('option').map((o) => o.textContent)
        expect(options).toContain('viewer')
        expect(options).toContain('analyst')
        expect(options).toContain('hunter')
        expect(options).toContain('engineer')
        expect(options).toContain('admin')
      })
    })
  })

  // =========================================================================
  // updateRole mutation
  // =========================================================================
  describe('updateRole mutation', () => {
    beforeEach(() => {
      mockPatch.mockResolvedValue({ data: {} })
    })

    it('calls apiClient.patch with the correct endpoint and role when dropdown changes', async () => {
      mockGet.mockResolvedValue({ data: [makeUser({ id: 'user-001', role: 'analyst' })] })
      renderPage()
      await waitFor(() => expect(screen.getByRole('combobox')).toBeInTheDocument())

      fireEvent.change(screen.getByRole('combobox'), { target: { value: 'hunter' } })

      await waitFor(() => {
        expect(mockPatch).toHaveBeenCalledWith('/users/user-001', { role: 'hunter' })
      })
    })

    it('invalidates the users query after a successful role update (triggers refetch)', async () => {
      mockGet
        .mockResolvedValueOnce({ data: [makeUser({ id: 'u1', role: 'analyst' })] })
        .mockResolvedValue({ data: [makeUser({ id: 'u1', role: 'hunter' })] })

      renderPage()
      // Wait for the user row to render (combobox appears once data loads)
      const select = await screen.findByRole('combobox')
      expect(mockGet).toHaveBeenCalledTimes(1)

      fireEvent.change(select, { target: { value: 'hunter' } })

      await waitFor(() => expect(mockGet).toHaveBeenCalledTimes(2))
    })
  })

  // =========================================================================
  // toggleActive mutation
  // =========================================================================
  describe('toggleActive mutation', () => {
    beforeEach(() => {
      mockPatch.mockResolvedValue({ data: {} })
    })

    it('calls apiClient.patch with is_active=false when "Disable" is clicked', async () => {
      mockGet.mockResolvedValue({ data: [makeUser({ id: 'user-001', is_active: true })] })
      renderPage()
      const btn = await screen.findByRole('button', { name: 'Disable' })
      fireEvent.click(btn)

      await waitFor(() => {
        expect(mockPatch).toHaveBeenCalledWith('/users/user-001', { is_active: false })
      })
    })

    it('calls apiClient.patch with is_active=true when "Enable" is clicked', async () => {
      mockGet.mockResolvedValue({ data: [makeUser({ id: 'user-002', is_active: false })] })
      renderPage()
      const btn = await screen.findByRole('button', { name: 'Enable' })
      fireEvent.click(btn)

      await waitFor(() => {
        expect(mockPatch).toHaveBeenCalledWith('/users/user-002', { is_active: true })
      })
    })

    it('invalidates the users query after toggling active (triggers refetch)', async () => {
      mockGet
        .mockResolvedValueOnce({ data: [makeUser({ id: 'u1', is_active: true })] })
        .mockResolvedValue({ data: [makeUser({ id: 'u1', is_active: false })] })

      renderPage()
      await waitFor(() => expect(mockGet).toHaveBeenCalledTimes(1))

      fireEvent.click(await screen.findByRole('button', { name: 'Disable' }))

      await waitFor(() => expect(mockGet).toHaveBeenCalledTimes(2))
    })
  })

  // =========================================================================
  // Role Permissions reference section
  // =========================================================================
  describe('role permissions section', () => {
    beforeEach(() => {
      mockGet.mockResolvedValue({ data: [] })
    })

    it('renders the "Role Permissions" heading', async () => {
      renderPage()
      await waitFor(() => expect(screen.getByText('Role Permissions')).toBeInTheDocument())
    })

    it('renders the "viewer" role card', async () => {
      renderPage()
      // There are two "viewer" labels (dropdown option + role card) — just check presence
      await waitFor(() => {
        const elements = screen.getAllByText('viewer')
        expect(elements.length).toBeGreaterThan(0)
      })
    })

    it('renders viewer role description', async () => {
      renderPage()
      await waitFor(() =>
        expect(screen.getByText('Read-only access to dashboards and alerts')).toBeInTheDocument(),
      )
    })

    it('renders analyst role description', async () => {
      renderPage()
      await waitFor(() =>
        expect(screen.getByText('View + investigate + resolve alerts')).toBeInTheDocument(),
      )
    })

    it('renders hunter role description', async () => {
      renderPage()
      await waitFor(() =>
        expect(screen.getByText('Analyst + query events + saved hunts')).toBeInTheDocument(),
      )
    })

    it('renders engineer role description', async () => {
      renderPage()
      await waitFor(() =>
        expect(screen.getByText('Hunter + manage rules + connectors')).toBeInTheDocument(),
      )
    })

    it('renders admin role description', async () => {
      renderPage()
      await waitFor(() =>
        expect(screen.getByText('Full access including user management')).toBeInTheDocument(),
      )
    })

    it('role permissions section is hidden when on the Audit Log tab', async () => {
      renderPage()
      await waitFor(() => expect(screen.getByText('Role Permissions')).toBeInTheDocument())
      fireEvent.click(screen.getByRole('button', { name: 'Audit Log' }))
      expect(screen.queryByText('Role Permissions')).not.toBeInTheDocument()
    })
  })

  // =========================================================================
  // API call — correct endpoint
  // =========================================================================
  describe('API call', () => {
    it('calls apiClient.get with "/users" to fetch the user list', async () => {
      mockGet.mockResolvedValue({ data: [] })
      renderPage()
      await waitFor(() => expect(mockGet).toHaveBeenCalledWith('/users'))
    })

    it('only calls apiClient.get once on initial mount', async () => {
      mockGet.mockResolvedValue({ data: [] })
      renderPage()
      await waitFor(() => expect(mockGet).toHaveBeenCalledTimes(1))
    })
  })

  // =========================================================================
  // MFA column — display
  // =========================================================================
  describe('MFA column', () => {
    it('renders the "MFA" column header', async () => {
      mockGet.mockResolvedValue({ data: [] })
      renderPage()
      await waitFor(() => expect(screen.getByText('MFA')).toBeInTheDocument())
    })

    it('shows "On" badge for users with MFA enabled', async () => {
      mockGet.mockResolvedValue({ data: [makeUser({ mfa_enabled: true })] })
      renderPage()
      await waitFor(() => expect(screen.getByText('On')).toBeInTheDocument())
    })

    it('shows "—" for users with MFA disabled', async () => {
      mockGet.mockResolvedValue({ data: [makeUser({ mfa_enabled: false })] })
      renderPage()
      await waitFor(() => expect(screen.getByText('—')).toBeInTheDocument())
    })

    it('does not show "On" badge when MFA is disabled', async () => {
      mockGet.mockResolvedValue({ data: [makeUser({ mfa_enabled: false })] })
      renderPage()
      await waitFor(() => expect(screen.queryByText('On')).not.toBeInTheDocument())
    })
  })

  // =========================================================================
  // MFA disable button — rendering
  // =========================================================================
  describe('MFA disable button — rendering', () => {
    it('renders the "MFA↓" button for users with MFA enabled', async () => {
      mockGet.mockResolvedValue({ data: [makeUser({ mfa_enabled: true })] })
      renderPage()
      await waitFor(() => expect(screen.getByRole('button', { name: 'MFA↓' })).toBeInTheDocument())
    })

    it('does not render "MFA↓" button for users with MFA disabled', async () => {
      mockGet.mockResolvedValue({ data: [makeUser({ mfa_enabled: false })] })
      renderPage()
      await waitFor(() => expect(screen.queryByRole('button', { name: 'MFA↓' })).not.toBeInTheDocument())
    })
  })

  // =========================================================================
  // MFA disable mutation
  // =========================================================================
  describe('MFA disable mutation', () => {
    beforeEach(() => {
      mockMfaDisable.mockResolvedValue({ message: 'MFA disabled' })
      vi.spyOn(window, 'confirm').mockReturnValue(true)
    })

    it('calls authApi.mfaDisable with the user id when confirmed', async () => {
      mockGet.mockResolvedValue({ data: [makeUser({ id: 'user-mfa', mfa_enabled: true })] })
      renderPage()

      const btn = await screen.findByRole('button', { name: 'MFA↓' })
      fireEvent.click(btn)

      await waitFor(() => {
        expect(mockMfaDisable).toHaveBeenCalledWith('user-mfa')
      })
    })

    it('does not call authApi.mfaDisable when the confirm dialog is cancelled', async () => {
      vi.spyOn(window, 'confirm').mockReturnValue(false)
      mockGet.mockResolvedValue({ data: [makeUser({ id: 'user-mfa', mfa_enabled: true })] })
      renderPage()

      const btn = await screen.findByRole('button', { name: 'MFA↓' })
      fireEvent.click(btn)

      expect(mockMfaDisable).not.toHaveBeenCalled()
    })

    it('shows the user email in the confirm dialog message', async () => {
      const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValue(false)
      mockGet.mockResolvedValue({ data: [makeUser({ id: 'u1', email: 'alice@mxtac.local', mfa_enabled: true })] })
      renderPage()

      const btn = await screen.findByRole('button', { name: 'MFA↓' })
      fireEvent.click(btn)

      expect(confirmSpy).toHaveBeenCalledWith('Disable MFA for alice@mxtac.local?')
    })

    it('invalidates the users query after successful MFA disable (triggers refetch)', async () => {
      mockGet
        .mockResolvedValueOnce({ data: [makeUser({ id: 'u1', mfa_enabled: true })] })
        .mockResolvedValue({ data: [makeUser({ id: 'u1', mfa_enabled: false })] })

      renderPage()
      const btn = await screen.findByRole('button', { name: 'MFA↓' })
      fireEvent.click(btn)

      await waitFor(() => expect(mockGet).toHaveBeenCalledTimes(2))
    })
  })
})
