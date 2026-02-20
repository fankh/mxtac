// vi.mock is hoisted before imports — declare all module mocks first.

vi.mock('../../lib/api', () => ({
  apiClient: {
    get:   vi.fn(),
    patch: vi.fn(),
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
import { apiClient } from '../../lib/api'

// ---------------------------------------------------------------------------
// Typed references to the mocked API
// ---------------------------------------------------------------------------

const mockGet   = apiClient.get   as ReturnType<typeof vi.fn>
const mockPatch = apiClient.patch as ReturnType<typeof vi.fn>

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
      expect(
        screen.getByText('Audit log coming soon — requires OpenSearch integration.'),
      ).toBeInTheDocument()
    })

    it('clicking "Audit Log" hides the users table', async () => {
      mockGet.mockResolvedValue({ data: [makeUser()] })
      renderPage()
      await waitFor(() => expect(screen.getByText('System Admin')).toBeInTheDocument())
      fireEvent.click(screen.getByRole('button', { name: 'Audit Log' }))
      expect(screen.queryByText('System Admin')).not.toBeInTheDocument()
    })

    it('clicking "Users & Roles" after switching back hides the audit placeholder', () => {
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Audit Log' }))
      fireEvent.click(screen.getByRole('button', { name: 'Users & Roles' }))
      expect(
        screen.queryByText('Audit log coming soon — requires OpenSearch integration.'),
      ).not.toBeInTheDocument()
    })
  })

  // =========================================================================
  // Audit Log tab content
  // =========================================================================
  describe('audit log tab', () => {
    it('shows the coming-soon placeholder', () => {
      renderPage()
      fireEvent.click(screen.getByRole('button', { name: 'Audit Log' }))
      expect(
        screen.getByText('Audit log coming soon — requires OpenSearch integration.'),
      ).toBeInTheDocument()
    })
  })

  // =========================================================================
  // Loading state
  // =========================================================================
  describe('loading state', () => {
    it('shows "Loading…" while the query is pending', () => {
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
  // Column headers
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
})
