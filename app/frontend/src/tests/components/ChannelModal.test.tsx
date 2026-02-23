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

import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ChannelModal } from '../../components/features/admin/ChannelModal'
import { notificationChannelsApi } from '../../lib/api'
import type { NotificationChannel } from '../../types/api'

// ---------------------------------------------------------------------------
// Typed mock references
// ---------------------------------------------------------------------------

const mockCreate = notificationChannelsApi.create as ReturnType<typeof vi.fn>
const mockUpdate = notificationChannelsApi.update as ReturnType<typeof vi.fn>

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

const makeChannel = (overrides: Partial<NotificationChannel> = {}): NotificationChannel => ({
  id:           1,
  name:         'SOC Email',
  channel_type: 'email',
  config: {
    smtp_host:    'smtp.example.com',
    smtp_port:    587,
    from_address: 'alerts@example.com',
    to_addresses: ['soc@example.com'],
    use_tls:      true,
  },
  enabled:      true,
  min_severity: 'high',
  created_at:   '2024-01-01T00:00:00Z',
  updated_at:   '2024-01-01T00:00:00Z',
  ...overrides,
})

// ---------------------------------------------------------------------------
// Render helpers
// ---------------------------------------------------------------------------

const onClose = vi.fn()
const onSaved = vi.fn()

function renderCreateModal() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <ChannelModal onClose={onClose} onSaved={onSaved} />
    </QueryClientProvider>,
  )
}

function renderEditModal(channel: NotificationChannel) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <ChannelModal channel={channel} onClose={onClose} onSaved={onSaved} />
    </QueryClientProvider>,
  )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('ChannelModal', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockCreate.mockReturnValue(new Promise<never>(() => {}))
    mockUpdate.mockReturnValue(new Promise<never>(() => {}))
  })

  // =========================================================================
  // Create mode — headings and basic structure
  // =========================================================================
  describe('create mode — structure', () => {
    it('renders "New Notification Channel" heading', () => {
      renderCreateModal()
      expect(screen.getByText('New Notification Channel')).toBeInTheDocument()
    })

    it('renders a "Channel Name" input', () => {
      renderCreateModal()
      expect(screen.getByPlaceholderText('e.g. SOC Slack Alerts')).toBeInTheDocument()
    })

    it('renders 4 channel type buttons', () => {
      renderCreateModal()
      expect(screen.getByRole('button', { name: 'Email' })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Slack' })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Webhook' })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Teams' })).toBeInTheDocument()
    })

    it('renders severity selector buttons', () => {
      renderCreateModal()
      expect(screen.getByRole('button', { name: 'critical' })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'high' })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'medium' })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'low' })).toBeInTheDocument()
    })

    it('renders "Create Channel" as save button text', () => {
      renderCreateModal()
      expect(screen.getByRole('button', { name: 'Create Channel' })).toBeInTheDocument()
    })

    it('renders a "Cancel" button', () => {
      renderCreateModal()
      expect(screen.getByRole('button', { name: 'Cancel' })).toBeInTheDocument()
    })
  })

  // =========================================================================
  // Create mode — Email config (default type)
  // =========================================================================
  describe('create mode — email config (default)', () => {
    it('shows SMTP host input by default', () => {
      renderCreateModal()
      expect(screen.getByPlaceholderText('smtp.example.com')).toBeInTheDocument()
    })

    it('shows From Address input', () => {
      renderCreateModal()
      expect(screen.getByPlaceholderText('alerts@example.com')).toBeInTheDocument()
    })

    it('shows To Addresses field with "Add" button', () => {
      renderCreateModal()
      // email input for adding addresses
      expect(screen.getByPlaceholderText('user@example.com')).toBeInTheDocument()
      expect(screen.getAllByRole('button', { name: 'Add' }).length).toBeGreaterThan(0)
    })

    it('shows Use TLS checkbox', () => {
      renderCreateModal()
      expect(screen.getByRole('checkbox')).toBeInTheDocument()
    })

    it('shows Username and Password fields', () => {
      renderCreateModal()
      expect(screen.getByPlaceholderText('smtp_user')).toBeInTheDocument()
    })
  })

  // =========================================================================
  // Create mode — type switching
  // =========================================================================
  describe('create mode — type switching', () => {
    it('shows Slack config when Slack type is selected', () => {
      renderCreateModal()
      fireEvent.click(screen.getByRole('button', { name: 'Slack' }))
      expect(screen.getByPlaceholderText('https://hooks.slack.com/services/...')).toBeInTheDocument()
    })

    it('shows channel override field in Slack config', () => {
      renderCreateModal()
      fireEvent.click(screen.getByRole('button', { name: 'Slack' }))
      expect(screen.getByPlaceholderText('#alerts')).toBeInTheDocument()
    })

    it('shows Webhook config when Webhook type is selected', () => {
      renderCreateModal()
      fireEvent.click(screen.getByRole('button', { name: 'Webhook' }))
      expect(screen.getByPlaceholderText('https://webhook.example.com/alerts')).toBeInTheDocument()
    })

    it('shows HTTP method selector in Webhook config', () => {
      renderCreateModal()
      fireEvent.click(screen.getByRole('button', { name: 'Webhook' }))
      const select = screen.getByRole('combobox') as HTMLSelectElement
      expect(select.value).toBe('POST')
    })

    it('shows Teams webhook URL field when Teams type is selected', () => {
      renderCreateModal()
      fireEvent.click(screen.getByRole('button', { name: 'Teams' }))
      expect(screen.getByPlaceholderText('https://outlook.office.com/webhook/...')).toBeInTheDocument()
    })

    it('hides Email config when Slack is selected', () => {
      renderCreateModal()
      fireEvent.click(screen.getByRole('button', { name: 'Slack' }))
      expect(screen.queryByPlaceholderText('smtp.example.com')).not.toBeInTheDocument()
    })
  })

  // =========================================================================
  // Create mode — to-addresses multi-input
  // =========================================================================
  describe('create mode — email to-addresses', () => {
    it('adds an address chip when "Add" button is clicked', () => {
      renderCreateModal()
      const toInput = screen.getByPlaceholderText('user@example.com')
      fireEvent.change(toInput, { target: { value: 'soc@example.com' } })
      fireEvent.click(screen.getAllByRole('button', { name: 'Add' })[0])
      expect(screen.getByText('soc@example.com')).toBeInTheDocument()
    })

    it('adds an address chip when Enter is pressed', () => {
      renderCreateModal()
      const toInput = screen.getByPlaceholderText('user@example.com')
      fireEvent.change(toInput, { target: { value: 'analyst@example.com' } })
      fireEvent.keyDown(toInput, { key: 'Enter' })
      expect(screen.getByText('analyst@example.com')).toBeInTheDocument()
    })

    it('does not add a duplicate address', () => {
      renderCreateModal()
      const toInput = screen.getByPlaceholderText('user@example.com')
      fireEvent.change(toInput, { target: { value: 'dup@example.com' } })
      fireEvent.keyDown(toInput, { key: 'Enter' })
      fireEvent.change(toInput, { target: { value: 'dup@example.com' } })
      fireEvent.keyDown(toInput, { key: 'Enter' })
      expect(screen.getAllByText('dup@example.com').length).toBe(1)
    })

    it('removes an address chip when × is clicked', () => {
      renderCreateModal()
      const toInput = screen.getByPlaceholderText('user@example.com')
      fireEvent.change(toInput, { target: { value: 'remove@example.com' } })
      fireEvent.keyDown(toInput, { key: 'Enter' })
      expect(screen.getByText('remove@example.com')).toBeInTheDocument()
      // find and click the × button next to the chip
      const removeBtn = screen.getByText('remove@example.com')
        .closest('span')!
        .querySelector('button')!
      fireEvent.click(removeBtn)
      expect(screen.queryByText('remove@example.com')).not.toBeInTheDocument()
    })
  })

  // =========================================================================
  // Create mode — webhook headers
  // =========================================================================
  describe('create mode — webhook headers', () => {
    it('adds a header row when Add button is clicked', () => {
      renderCreateModal()
      fireEvent.click(screen.getByRole('button', { name: 'Webhook' }))
      const keyInput = screen.getByPlaceholderText('Header name')
      const valInput = screen.getByPlaceholderText('Value')
      fireEvent.change(keyInput, { target: { value: 'X-Custom' } })
      fireEvent.change(valInput, { target: { value: 'my-value' } })
      fireEvent.click(screen.getByRole('button', { name: 'Add' }))
      expect(screen.getByText('X-Custom:')).toBeInTheDocument()
      expect(screen.getByText('my-value')).toBeInTheDocument()
    })

    it('removes a header row when × is clicked', () => {
      renderCreateModal()
      fireEvent.click(screen.getByRole('button', { name: 'Webhook' }))
      fireEvent.change(screen.getByPlaceholderText('Header name'), { target: { value: 'X-Test' } })
      fireEvent.change(screen.getByPlaceholderText('Value'), { target: { value: 'abc' } })
      fireEvent.click(screen.getByRole('button', { name: 'Add' }))
      expect(screen.getByText('X-Test:')).toBeInTheDocument()
      // find × button for the header row
      const removeBtn = screen.getByText('X-Test:')
        .closest('div')!
        .querySelector('button')!
      fireEvent.click(removeBtn)
      expect(screen.queryByText('X-Test:')).not.toBeInTheDocument()
    })
  })

  // =========================================================================
  // Create mode — Cancel button
  // =========================================================================
  describe('cancel button', () => {
    it('calls onClose when Cancel is clicked', () => {
      renderCreateModal()
      fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
      expect(onClose).toHaveBeenCalledTimes(1)
    })

    it('calls onClose when × header button is clicked', () => {
      renderCreateModal()
      // The × close button in the header
      const closeBtn = screen.getByText('×')
      fireEvent.click(closeBtn)
      expect(onClose).toHaveBeenCalledTimes(1)
    })
  })

  // =========================================================================
  // Create mode — save mutation
  // =========================================================================
  describe('create mode — save', () => {
    it('calls notificationChannelsApi.create when save button is clicked', async () => {
      mockCreate.mockResolvedValue(makeChannel())
      renderCreateModal()
      fireEvent.change(screen.getByPlaceholderText('e.g. SOC Slack Alerts'), {
        target: { value: 'My Email' },
      })
      fireEvent.click(screen.getByRole('button', { name: 'Create Channel' }))
      await waitFor(() => expect(mockCreate).toHaveBeenCalledTimes(1))
    })

    it('sends name and channel_type in the create payload', async () => {
      mockCreate.mockResolvedValue(makeChannel())
      renderCreateModal()
      fireEvent.change(screen.getByPlaceholderText('e.g. SOC Slack Alerts'), {
        target: { value: 'Team Email' },
      })
      fireEvent.click(screen.getByRole('button', { name: 'Create Channel' }))
      await waitFor(() => {
        const payload = mockCreate.mock.calls[0][0]
        expect(payload.name).toBe('Team Email')
        expect(payload.channel_type).toBe('email')
      })
    })

    it('shows "Saving…" on the button while the mutation is pending', async () => {
      renderCreateModal()
      fireEvent.change(screen.getByPlaceholderText('e.g. SOC Slack Alerts'), {
        target: { value: 'Channel' },
      })
      fireEvent.click(screen.getByRole('button', { name: 'Create Channel' }))
      await waitFor(() =>
        expect(screen.getByRole('button', { name: 'Saving…' })).toBeInTheDocument(),
      )
    })

    it('calls onClose after successful save', async () => {
      mockCreate.mockResolvedValue(makeChannel())
      renderCreateModal()
      fireEvent.change(screen.getByPlaceholderText('e.g. SOC Slack Alerts'), {
        target: { value: 'My Channel' },
      })
      fireEvent.click(screen.getByRole('button', { name: 'Create Channel' }))
      await waitFor(() => expect(onClose).toHaveBeenCalledTimes(1))
    })

    it('calls onSaved after successful save', async () => {
      mockCreate.mockResolvedValue(makeChannel())
      renderCreateModal()
      fireEvent.change(screen.getByPlaceholderText('e.g. SOC Slack Alerts'), {
        target: { value: 'My Channel' },
      })
      fireEvent.click(screen.getByRole('button', { name: 'Create Channel' }))
      await waitFor(() => expect(onSaved).toHaveBeenCalledTimes(1))
    })
  })

  // =========================================================================
  // Edit mode — structure
  // =========================================================================
  describe('edit mode — structure', () => {
    it('renders "Edit: SOC Email" heading for an email channel', () => {
      renderEditModal(makeChannel({ name: 'SOC Email' }))
      expect(screen.getByText('Edit: SOC Email')).toBeInTheDocument()
    })

    it('does NOT render the channel name text input in edit mode', () => {
      renderEditModal(makeChannel())
      expect(screen.queryByPlaceholderText('e.g. SOC Slack Alerts')).not.toBeInTheDocument()
    })

    it('shows the channel type as read-only text', () => {
      renderEditModal(makeChannel({ channel_type: 'email' }))
      expect(screen.getByText('Email')).toBeInTheDocument()
      // type selector buttons should not be present
      expect(screen.queryByRole('button', { name: 'Slack' })).not.toBeInTheDocument()
    })

    it('renders "Save Changes" as save button text', () => {
      renderEditModal(makeChannel())
      expect(screen.getByRole('button', { name: 'Save Changes' })).toBeInTheDocument()
    })

    it('pre-fills SMTP host from channel config', () => {
      renderEditModal(makeChannel({
        channel_type: 'email',
        config: { smtp_host: 'mail.corp.com', smtp_port: 465, from_address: '', to_addresses: [], use_tls: true },
      }))
      expect(screen.getByDisplayValue('mail.corp.com')).toBeInTheDocument()
    })

    it('pre-fills slack webhook URL from channel config', () => {
      renderEditModal(makeChannel({
        channel_type: 'slack',
        config: { webhook_url: 'https://hooks.slack.com/services/TEST' },
      }))
      expect(screen.getByDisplayValue('https://hooks.slack.com/services/TEST')).toBeInTheDocument()
    })
  })

  // =========================================================================
  // Edit mode — save mutation
  // =========================================================================
  describe('edit mode — save', () => {
    it('calls notificationChannelsApi.update when save button is clicked', async () => {
      mockUpdate.mockResolvedValue(makeChannel())
      renderEditModal(makeChannel({ id: 42 }))
      fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }))
      await waitFor(() => expect(mockUpdate).toHaveBeenCalledWith(42, expect.any(Object)))
    })

    it('sends min_severity in the update payload', async () => {
      mockUpdate.mockResolvedValue(makeChannel())
      renderEditModal(makeChannel({ id: 42, min_severity: 'critical' }))
      fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }))
      await waitFor(() => {
        const payload = mockUpdate.mock.calls[0][1]
        expect(payload.min_severity).toBe('critical')
      })
    })

    it('shows "Saving…" on the button while the mutation is pending', async () => {
      renderEditModal(makeChannel({ id: 42 }))
      fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }))
      await waitFor(() =>
        expect(screen.getByRole('button', { name: 'Saving…' })).toBeInTheDocument(),
      )
    })

    it('calls onClose after successful update', async () => {
      mockUpdate.mockResolvedValue(makeChannel())
      renderEditModal(makeChannel({ id: 42 }))
      fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }))
      await waitFor(() => expect(onClose).toHaveBeenCalledTimes(1))
    })
  })
})
