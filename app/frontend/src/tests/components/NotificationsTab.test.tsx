// vi.mock is hoisted before imports — declare all module mocks first.

vi.mock('../../lib/api', () => ({
  notificationChannelsApi: {
    list:   vi.fn(),
    get:    vi.fn(),
    create: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
    test:   vi.fn(),
  },
}))

vi.mock('../../stores/uiStore', () => ({
  useUIStore: () => ({ addNotification: vi.fn() }),
}))

// Stub ChannelModal — tested separately
vi.mock('../../components/features/admin/ChannelModal', () => ({
  ChannelModal: ({ onClose }: { channel?: unknown; onClose: () => void; onSaved: () => void }) => (
    <div data-testid="channel-modal">
      <button onClick={onClose}>Close Modal</button>
    </div>
  ),
}))

import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { NotificationsTab } from '../../components/features/admin/NotificationsTab'
import { notificationChannelsApi } from '../../lib/api'

// ---------------------------------------------------------------------------
// Typed mock references
// ---------------------------------------------------------------------------

const mockList   = notificationChannelsApi.list   as ReturnType<typeof vi.fn>
const mockUpdate = notificationChannelsApi.update as ReturnType<typeof vi.fn>
const mockDelete = notificationChannelsApi.delete as ReturnType<typeof vi.fn>
const mockTest   = notificationChannelsApi.test   as ReturnType<typeof vi.fn>

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

const makeChannel = (overrides: Record<string, unknown> = {}) => ({
  id:           1,
  name:         'SOC Email',
  channel_type: 'email',
  config:       { smtp_host: 'smtp.example.com', smtp_port: 587 },
  enabled:      true,
  min_severity: 'high',
  created_at:   '2024-01-01T00:00:00Z',
  updated_at:   '2024-01-01T00:00:00Z',
  ...overrides,
})

const makeListResponse = (items: unknown[] = []) => ({
  items,
  pagination: { page: 1, page_size: 100, total: items.length, total_pages: 1 },
})

// ---------------------------------------------------------------------------
// Render helper
// ---------------------------------------------------------------------------

function renderTab() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: Infinity } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <NotificationsTab />
    </QueryClientProvider>,
  )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('NotificationsTab', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    // Default: pending forever → loading state
    mockList.mockReturnValue(new Promise<never>(() => {}))
    mockUpdate.mockReturnValue(new Promise<never>(() => {}))
    mockDelete.mockReturnValue(new Promise<never>(() => {}))
    mockTest.mockReturnValue(new Promise<never>(() => {}))
  })

  // =========================================================================
  // Header
  // =========================================================================
  describe('header', () => {
    it('renders "Notification Channels" heading', () => {
      renderTab()
      expect(screen.getByText('Notification Channels')).toBeInTheDocument()
    })

    it('renders the description text', () => {
      renderTab()
      expect(screen.getByText(/Configure where alerts are delivered/)).toBeInTheDocument()
    })

    it('renders the "+ Add Channel" button', () => {
      renderTab()
      expect(screen.getByRole('button', { name: '+ Add Channel' })).toBeInTheDocument()
    })
  })

  // =========================================================================
  // Loading state
  // =========================================================================
  describe('loading state', () => {
    it('shows "Loading…" while the query is pending', () => {
      renderTab()
      expect(screen.getByText('Loading…')).toBeInTheDocument()
    })

    it('does not show any channel cards while loading', () => {
      renderTab()
      expect(screen.queryByText('SOC Email')).not.toBeInTheDocument()
    })
  })

  // =========================================================================
  // Empty state
  // =========================================================================
  describe('empty state', () => {
    beforeEach(() => {
      mockList.mockResolvedValue(makeListResponse([]))
    })

    it('shows "No notification channels configured." when empty', async () => {
      renderTab()
      await waitFor(() =>
        expect(screen.getByText('No notification channels configured.')).toBeInTheDocument(),
      )
    })

    it('shows "Add your first channel" link when empty', async () => {
      renderTab()
      await waitFor(() =>
        expect(screen.getByRole('button', { name: 'Add your first channel' })).toBeInTheDocument(),
      )
    })

    it('does not show "Loading…" in empty state', async () => {
      renderTab()
      await waitFor(() => expect(screen.queryByText('Loading…')).not.toBeInTheDocument())
    })
  })

  // =========================================================================
  // Success state — channel card rendering
  // =========================================================================
  describe('channel card rendering', () => {
    it('renders a channel name', async () => {
      mockList.mockResolvedValue(makeListResponse([makeChannel({ name: 'SOC Email' })]))
      renderTab()
      await waitFor(() => expect(screen.getByText('SOC Email')).toBeInTheDocument())
    })

    it('renders "Email" type label for email channels', async () => {
      mockList.mockResolvedValue(makeListResponse([makeChannel({ channel_type: 'email' })]))
      renderTab()
      await waitFor(() => expect(screen.getByText('Email')).toBeInTheDocument())
    })

    it('renders "Slack" type label for slack channels', async () => {
      mockList.mockResolvedValue(makeListResponse([makeChannel({ channel_type: 'slack' })]))
      renderTab()
      await waitFor(() => expect(screen.getByText('Slack')).toBeInTheDocument())
    })

    it('renders "Webhook" type label for webhook channels', async () => {
      mockList.mockResolvedValue(makeListResponse([makeChannel({ channel_type: 'webhook' })]))
      renderTab()
      await waitFor(() => expect(screen.getByText('Webhook')).toBeInTheDocument())
    })

    it('renders "Microsoft Teams" type label for msteams channels', async () => {
      mockList.mockResolvedValue(makeListResponse([makeChannel({ channel_type: 'msteams' })]))
      renderTab()
      await waitFor(() => expect(screen.getByText('Microsoft Teams')).toBeInTheDocument())
    })

    it('renders "On" badge for enabled channels', async () => {
      mockList.mockResolvedValue(makeListResponse([makeChannel({ enabled: true })]))
      renderTab()
      await waitFor(() => expect(screen.getByRole('button', { name: 'On' })).toBeInTheDocument())
    })

    it('renders "Off" badge for disabled channels', async () => {
      mockList.mockResolvedValue(makeListResponse([makeChannel({ enabled: false })]))
      renderTab()
      await waitFor(() => expect(screen.getByRole('button', { name: 'Off' })).toBeInTheDocument())
    })

    it('renders the min_severity badge', async () => {
      mockList.mockResolvedValue(makeListResponse([makeChannel({ min_severity: 'critical' })]))
      renderTab()
      await waitFor(() => expect(screen.getByText('critical')).toBeInTheDocument())
    })

    it('renders Test, Edit, Delete action buttons', async () => {
      mockList.mockResolvedValue(makeListResponse([makeChannel()]))
      renderTab()
      await waitFor(() => {
        expect(screen.getByRole('button', { name: 'Test' })).toBeInTheDocument()
        expect(screen.getByRole('button', { name: 'Edit' })).toBeInTheDocument()
        expect(screen.getByRole('button', { name: 'Delete' })).toBeInTheDocument()
      })
    })

    it('renders multiple channel cards', async () => {
      mockList.mockResolvedValue(makeListResponse([
        makeChannel({ id: 1, name: 'Email Channel' }),
        makeChannel({ id: 2, name: 'Slack Channel', channel_type: 'slack' }),
      ]))
      renderTab()
      await waitFor(() => {
        expect(screen.getByText('Email Channel')).toBeInTheDocument()
        expect(screen.getByText('Slack Channel')).toBeInTheDocument()
      })
    })
  })

  // =========================================================================
  // Enabled toggle
  // =========================================================================
  describe('enabled toggle', () => {
    beforeEach(() => {
      mockUpdate.mockResolvedValue({})
      mockList.mockResolvedValue(makeListResponse([makeChannel({ id: 5, enabled: true })]))
    })

    it('calls notificationChannelsApi.update with enabled=false when "On" is clicked', async () => {
      renderTab()
      const toggleBtn = await screen.findByRole('button', { name: 'On' })
      fireEvent.click(toggleBtn)
      await waitFor(() =>
        expect(mockUpdate).toHaveBeenCalledWith(5, { enabled: false }),
      )
    })

    it('calls notificationChannelsApi.update with enabled=true when "Off" is clicked', async () => {
      mockList.mockResolvedValue(makeListResponse([makeChannel({ id: 7, enabled: false })]))
      renderTab()
      const toggleBtn = await screen.findByRole('button', { name: 'Off' })
      fireEvent.click(toggleBtn)
      await waitFor(() =>
        expect(mockUpdate).toHaveBeenCalledWith(7, { enabled: true }),
      )
    })

    it('re-fetches the channel list after a successful toggle (invalidates query)', async () => {
      mockList
        .mockResolvedValueOnce(makeListResponse([makeChannel({ id: 5, enabled: true })]))
        .mockResolvedValue(makeListResponse([makeChannel({ id: 5, enabled: false })]))
      renderTab()
      fireEvent.click(await screen.findByRole('button', { name: 'On' }))
      await waitFor(() => expect(mockList).toHaveBeenCalledTimes(2))
    })
  })

  // =========================================================================
  // Delete mutation
  // =========================================================================
  describe('delete mutation', () => {
    beforeEach(() => {
      mockDelete.mockResolvedValue(undefined)
      vi.spyOn(window, 'confirm').mockReturnValue(true)
    })

    it('calls notificationChannelsApi.delete when "Delete" is clicked and confirmed', async () => {
      mockList.mockResolvedValue(makeListResponse([makeChannel({ id: 3 })]))
      renderTab()
      fireEvent.click(await screen.findByRole('button', { name: 'Delete' }))
      await waitFor(() => expect(mockDelete).toHaveBeenCalledWith(3))
    })

    it('does not call delete when the confirm dialog is cancelled', async () => {
      vi.spyOn(window, 'confirm').mockReturnValue(false)
      mockList.mockResolvedValue(makeListResponse([makeChannel({ id: 3 })]))
      renderTab()
      fireEvent.click(await screen.findByRole('button', { name: 'Delete' }))
      expect(mockDelete).not.toHaveBeenCalled()
    })

    it('includes the channel name in the confirm dialog message', async () => {
      const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValue(false)
      mockList.mockResolvedValue(makeListResponse([makeChannel({ name: 'My Slack' })]))
      renderTab()
      fireEvent.click(await screen.findByRole('button', { name: 'Delete' }))
      expect(confirmSpy).toHaveBeenCalledWith(expect.stringContaining('My Slack'))
    })

    it('re-fetches the channel list after successful delete', async () => {
      mockList
        .mockResolvedValueOnce(makeListResponse([makeChannel({ id: 3 })]))
        .mockResolvedValue(makeListResponse([]))
      renderTab()
      fireEvent.click(await screen.findByRole('button', { name: 'Delete' }))
      await waitFor(() => expect(mockList).toHaveBeenCalledTimes(2))
    })
  })

  // =========================================================================
  // Test mutation
  // =========================================================================
  describe('test mutation', () => {
    it('calls notificationChannelsApi.test when "Test" is clicked', async () => {
      mockList.mockResolvedValue(makeListResponse([makeChannel({ id: 9 })]))
      mockTest.mockResolvedValue({ channel_id: 9, sent: true, message: 'Test sent OK' })
      renderTab()
      fireEvent.click(await screen.findByRole('button', { name: 'Test' }))
      await waitFor(() => expect(mockTest).toHaveBeenCalledWith(9))
    })

    it('shows "Last test: Passed" after a successful test', async () => {
      mockList.mockResolvedValue(makeListResponse([makeChannel({ id: 9 })]))
      mockTest.mockResolvedValue({ channel_id: 9, sent: true, message: 'OK' })
      renderTab()
      fireEvent.click(await screen.findByRole('button', { name: 'Test' }))
      await waitFor(() => expect(screen.getByText('Last test: Passed')).toBeInTheDocument())
    })

    it('shows "Last test: Failed" after a failed test', async () => {
      mockList.mockResolvedValue(makeListResponse([makeChannel({ id: 9 })]))
      mockTest.mockResolvedValue({ channel_id: 9, sent: false, message: 'Timeout' })
      renderTab()
      fireEvent.click(await screen.findByRole('button', { name: 'Test' }))
      await waitFor(() => expect(screen.getByText('Last test: Failed')).toBeInTheDocument())
    })
  })

  // =========================================================================
  // Modal — create
  // =========================================================================
  describe('create modal', () => {
    beforeEach(() => {
      mockList.mockResolvedValue(makeListResponse([]))
    })

    it('does not show the modal initially', async () => {
      renderTab()
      await waitFor(() => expect(screen.queryByTestId('channel-modal')).not.toBeInTheDocument())
    })

    it('opens the modal when "+ Add Channel" is clicked', async () => {
      renderTab()
      await waitFor(() => expect(screen.queryByText('Loading…')).not.toBeInTheDocument())
      fireEvent.click(screen.getByRole('button', { name: '+ Add Channel' }))
      expect(screen.getByTestId('channel-modal')).toBeInTheDocument()
    })

    it('opens the modal when "Add your first channel" link is clicked', async () => {
      renderTab()
      const link = await screen.findByRole('button', { name: 'Add your first channel' })
      fireEvent.click(link)
      expect(screen.getByTestId('channel-modal')).toBeInTheDocument()
    })

    it('closes the modal when the modal calls onClose', async () => {
      renderTab()
      await waitFor(() => expect(screen.queryByText('Loading…')).not.toBeInTheDocument())
      fireEvent.click(screen.getByRole('button', { name: '+ Add Channel' }))
      expect(screen.getByTestId('channel-modal')).toBeInTheDocument()
      fireEvent.click(screen.getByRole('button', { name: 'Close Modal' }))
      expect(screen.queryByTestId('channel-modal')).not.toBeInTheDocument()
    })
  })

  // =========================================================================
  // Modal — edit
  // =========================================================================
  describe('edit modal', () => {
    it('opens the modal when "Edit" is clicked on a channel', async () => {
      mockList.mockResolvedValue(makeListResponse([makeChannel({ id: 1 })]))
      renderTab()
      fireEvent.click(await screen.findByRole('button', { name: 'Edit' }))
      expect(screen.getByTestId('channel-modal')).toBeInTheDocument()
    })

    it('closes the edit modal when the modal calls onClose', async () => {
      mockList.mockResolvedValue(makeListResponse([makeChannel({ id: 1 })]))
      renderTab()
      fireEvent.click(await screen.findByRole('button', { name: 'Edit' }))
      fireEvent.click(screen.getByRole('button', { name: 'Close Modal' }))
      expect(screen.queryByTestId('channel-modal')).not.toBeInTheDocument()
    })
  })

  // =========================================================================
  // API call
  // =========================================================================
  describe('API call', () => {
    it('calls notificationChannelsApi.list with page_size=100 on mount', async () => {
      mockList.mockResolvedValue(makeListResponse([]))
      renderTab()
      await waitFor(() =>
        expect(mockList).toHaveBeenCalledWith({ page_size: 100 }),
      )
    })
  })
})
