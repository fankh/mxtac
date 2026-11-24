// vi.mock is hoisted before imports — declare all module mocks first.

vi.mock('../../lib/api', async (importOriginal) => {
  const actual = await importOriginal<typeof ApiModule>()
  return {
    ...actual,
    connectorsApi: {
      list: vi.fn(),
      get: vi.fn(),
      create: vi.fn(),
      update: vi.fn(),
      delete: vi.fn(),
      health: vi.fn(),
      start: vi.fn(),
      stop: vi.fn(),
      test: vi.fn(),
    },
    ingestApi: { send: vi.fn() },
  }
})

// The real TopBar opens the alert WebSocket; the page frame only needs its slots.
vi.mock('../../components/layout/TopBar', () => ({
  TopBar: ({ crumb, actions }: { crumb: string; actions?: ReactNode }) => (
    <header>
      <h1>{crumb}</h1>
      {actions}
    </header>
  ),
}))

import type { ReactNode } from 'react'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { SourcesPage } from '../../components/features/sources/SourcesPage'
import type * as ApiModule from '../../lib/api'
import { connectorsApi, ingestApi } from '../../lib/api'
import { useUIStore } from '../../stores/uiStore'
import type { Connector } from '../../types/api'
import { installRadixSelectPolyfills } from '../mocks/radixSelect'

// A Radix Switch inside a form measures itself with ResizeObserver, which jsdom lacks.
installRadixSelectPolyfills()

const api = vi.mocked(connectorsApi)
const sendMock = vi.mocked(ingestApi.send)

function makeConnector(overrides: Partial<Connector> = {}): Connector {
  return {
    id: 'conn-wazuh',
    name: 'wazuh-prod',
    connector_type: 'wazuh',
    status: 'active',
    enabled: true,
    events_total: 1200,
    errors_total: 0,
    last_seen_at: '2026-02-19T08:30:00+00:00',
    error_message: null,
    ...overrides,
  }
}

const WAZUH = makeConnector()
const ZEEK = makeConnector({
  id: 'conn-zeek', name: 'zeek-dmz', connector_type: 'zeek', status: 'error', events_total: 300, errors_total: 4,
  error_message: 'Zeek log directory not found: /opt/zeek/logs/current',
})
const SYSLOG = makeConnector({
  id: 'conn-syslog', name: 'fw-syslog', connector_type: 'syslog', status: 'inactive', enabled: false, events_total: 0,
  last_seen_at: null,
})
const WEBHOOK = makeConnector({
  id: 'conn-hook', name: 'my-webhook', connector_type: 'generic', status: 'inactive', events_total: 5, last_seen_at: null,
})
const ALL = [WAZUH, ZEEK, SYSLOG, WEBHOOK]

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <SourcesPage />
    </QueryClientProvider>,
  )
}

async function renderLoaded() {
  const view = renderPage()
  await screen.findByText('wazuh-prod')
  return view
}

function rowOf(name: string): HTMLElement {
  return screen.getByRole('button', { name }).closest('tr') as HTMLElement
}

function notifications() {
  return useUIStore.getState().notifications
}

beforeEach(() => {
  vi.clearAllMocks()
  useUIStore.setState({ notifications: [] })
  api.list.mockResolvedValue(ALL)
  api.health.mockResolvedValue({ ...WAZUH, healthy: true })
})

describe('SourcesPage', () => {
  describe('list', () => {
    it('shows a loading skeleton while sources load', () => {
      api.list.mockReturnValue(new Promise<Connector[]>(() => {}))
      renderPage()
      expect(screen.getByLabelText('Loading sources')).toBeInTheDocument()
    })

    it('lists each source with its type, status and counters', async () => {
      await renderLoaded()
      const wazuh = rowOf('wazuh-prod')
      expect(within(wazuh).getByText('Wazuh')).toBeInTheDocument()
      expect(within(wazuh).getByText('Active')).toBeInTheDocument()
      expect(within(wazuh).getByText('1,200')).toBeInTheDocument()

      const zeek = rowOf('zeek-dmz')
      expect(within(zeek).getByText('Error')).toHaveAttribute('title', 'Zeek log directory not found: /opt/zeek/logs/current')
      expect(within(zeek).getByText('4')).toBeInTheDocument()
      expect(within(rowOf('fw-syslog')).getByText('Never')).toBeInTheDocument()
    })

    it('summarises sources, running, errors and events', async () => {
      await renderLoaded()
      const card = (label: string) => screen.getByText(label, { selector: 'p' }).parentElement as HTMLElement
      expect(within(card('Sources')).getByText('4')).toBeInTheDocument()
      expect(within(card('Running')).getByText('1')).toBeInTheDocument()
      expect(within(card('In error')).getByText('1')).toBeInTheDocument()
      expect(within(card('Events received')).getByText('1,505')).toBeInTheDocument()
    })

    it('shows an empty state when no source is configured', async () => {
      api.list.mockResolvedValue([])
      renderPage()
      expect(await screen.findByText('No data sources yet')).toBeInTheDocument()
    })

    it('shows an error with Retry when the request fails, and reloads on Retry', async () => {
      api.list.mockRejectedValueOnce(new Error('boom'))
      renderPage()
      expect(await screen.findByText('Could not load data sources.')).toBeInTheDocument()
      fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
      expect(await screen.findByText('wazuh-prod')).toBeInTheDocument()
    })

    it('filters by search text, cleared with Escape', async () => {
      await renderLoaded()
      const search = screen.getByLabelText('Search sources') as HTMLInputElement
      fireEvent.change(search, { target: { value: 'zeek' } })
      expect(screen.queryByText('wazuh-prod')).not.toBeInTheDocument()
      expect(screen.getByText('zeek-dmz')).toBeInTheDocument()
      fireEvent.keyDown(search, { key: 'Escape' })
      expect(search.value).toBe('')
      expect(screen.getByText('wazuh-prod')).toBeInTheDocument()
    })

    it('filters by source type', async () => {
      await renderLoaded()
      fireEvent.click(screen.getByRole('button', { name: 'Syslog' }))
      expect(screen.queryByText('wazuh-prod')).not.toBeInTheDocument()
      expect(screen.getByText('fw-syslog')).toBeInTheDocument()
      fireEvent.click(screen.getByRole('button', { name: 'All' }))
      expect(screen.getByText('wazuh-prod')).toBeInTheDocument()
    })
  })

  describe('row actions', () => {
    it('toggles the enabled setting through PATCH /connectors/{id}', async () => {
      api.update.mockResolvedValue({ ...WAZUH, enabled: false })
      await renderLoaded()
      fireEvent.click(screen.getByRole('switch', { name: 'Disable wazuh-prod' }))
      await waitFor(() => expect(api.update).toHaveBeenCalledWith('conn-wazuh', { enabled: false }))
    })

    it('offers Stop for a running source and Start for a stopped one', async () => {
      api.stop.mockResolvedValue({ ...WAZUH, status: 'inactive' })
      api.start.mockResolvedValue({ ...SYSLOG, status: 'connecting' })
      await renderLoaded()
      expect(screen.queryByTitle('Start wazuh-prod')).not.toBeInTheDocument()
      fireEvent.click(screen.getByTitle('Stop wazuh-prod'))
      await waitFor(() => expect(api.stop).toHaveBeenCalledWith('conn-wazuh'))
      fireEvent.click(screen.getByTitle('Start fw-syslog'))
      await waitFor(() => expect(api.start).toHaveBeenCalledWith('conn-syslog'))
    })

    it('reports a failed start with the server message', async () => {
      api.start.mockRejectedValue({ response: { data: { detail: 'Message queue not available' } } })
      await renderLoaded()
      fireEvent.click(screen.getByTitle('Start fw-syslog'))
      await waitFor(() => expect(notifications()).toHaveLength(1))
      expect(notifications()[0]).toMatchObject({ type: 'error', message: 'Message queue not available' })
    })

    it('runs a connection test and reports the result', async () => {
      api.test.mockResolvedValue({ connector_id: 'conn-zeek', reachable: false, message: 'Zeek log directory not found: /x' })
      await renderLoaded()
      fireEvent.click(screen.getByTitle('Test connection to zeek-dmz'))
      await waitFor(() => expect(api.test).toHaveBeenCalledWith('conn-zeek'))
      await waitFor(() => expect(notifications()).toHaveLength(1))
      expect(notifications()[0]).toMatchObject({
        type: 'warning', title: 'zeek-dmz is not reachable', message: 'Zeek log directory not found: /x',
      })
    })

    it('hides actions the backend does not support for a type', async () => {
      await renderLoaded()
      // Syslog has no connection test; a generic webhook has no runtime to start and no test.
      expect(screen.queryByTitle('Test connection to fw-syslog')).not.toBeInTheDocument()
      expect(screen.queryByTitle('Start my-webhook')).not.toBeInTheDocument()
      expect(screen.queryByTitle('Test connection to my-webhook')).not.toBeInTheDocument()
      expect(screen.getByTitle('Edit my-webhook')).toBeInTheDocument()
    })

    it('deletes a stopped source after confirmation', async () => {
      api.delete.mockResolvedValue(undefined)
      await renderLoaded()
      fireEvent.click(screen.getByTitle('Delete fw-syslog'))
      const dialog = await screen.findByRole('dialog')
      fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }))
      await waitFor(() => expect(api.delete).toHaveBeenCalledWith('conn-syslog'))
      expect(api.stop).not.toHaveBeenCalled()
    })

    it('stops a running source before deleting it', async () => {
      api.stop.mockResolvedValue({ ...WAZUH, status: 'inactive' })
      api.delete.mockResolvedValue(undefined)
      await renderLoaded()
      fireEvent.click(screen.getByTitle('Delete wazuh-prod'))
      const dialog = await screen.findByRole('dialog')
      fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }))
      await waitFor(() => expect(api.delete).toHaveBeenCalledWith('conn-wazuh'))
      expect(api.stop).toHaveBeenCalledWith('conn-wazuh')
    })

    it('opens the detail panel with live health', async () => {
      await renderLoaded()
      fireEvent.click(screen.getByRole('button', { name: 'wazuh-prod' }))
      const panel = await screen.findByRole('dialog')
      expect(await within(panel).findByText('Healthy')).toBeInTheDocument()
      expect(api.health).toHaveBeenCalledWith('conn-wazuh')
      expect(within(panel).getByText('conn-wazuh')).toBeInTheDocument()
    })
  })

  describe('add and edit', () => {
    async function openAdd() {
      await renderLoaded()
      fireEvent.click(screen.getByRole('button', { name: 'Add source' }))
      return screen.findByRole('dialog')
    }

    it('offers only the five supported types', async () => {
      const dialog = await openAdd()
      const types = within(dialog).getAllByRole('button', { pressed: false })
        .concat(within(dialog).getAllByRole('button', { pressed: true }))
        .map((b) => b.textContent)
      expect([...types].sort()).toEqual(['Generic webhook', 'Suricata', 'Syslog', 'Wazuh', 'Zeek'])
    })

    it('creates a Wazuh source with the config keys the connector reads', async () => {
      api.create.mockResolvedValue(makeConnector({ id: 'conn-new', name: 'wazuh-lab', status: 'connecting' }))
      const dialog = await openAdd()
      fireEvent.change(within(dialog).getByLabelText('Name'), { target: { value: 'wazuh-lab' } })
      fireEvent.change(within(dialog).getByLabelText(/Manager API URL/), { target: { value: 'https://wazuh.lab:55000' } })
      fireEvent.change(within(dialog).getByLabelText(/Username/), { target: { value: 'wazuh-wui' } })
      fireEvent.change(within(dialog).getByLabelText(/Password/), { target: { value: 's3cret' } })
      fireEvent.change(within(dialog).getByLabelText(/Poll interval/), { target: { value: '30' } })
      fireEvent.click(within(dialog).getByRole('button', { name: 'Add source' }))
      await waitFor(() => expect(api.create).toHaveBeenCalledTimes(1))
      expect(api.create).toHaveBeenCalledWith({
        name: 'wazuh-lab',
        connector_type: 'wazuh',
        config: {
          url: 'https://wazuh.lab:55000', username: 'wazuh-wui', password: 's3cret', verify_ssl: true,
          poll_interval_seconds: 30,
        },
        enabled: true,
      })
    })

    it('requires the name and the required fields of the type', async () => {
      const dialog = await openAdd()
      fireEvent.click(within(dialog).getByRole('button', { name: 'Add source' }))
      expect(within(dialog).getByRole('alert')).toHaveTextContent('Name is required')
      fireEvent.change(within(dialog).getByLabelText('Name'), { target: { value: 'wazuh-lab' } })
      fireEvent.click(within(dialog).getByRole('button', { name: 'Add source' }))
      expect(within(dialog).getByRole('alert')).toHaveTextContent('Required: Manager API URL, Username, Password')
      expect(api.create).not.toHaveBeenCalled()
    })

    it('sends list fields as arrays and leaves empty fields to the connector defaults', async () => {
      api.create.mockResolvedValue(makeConnector({ id: 'conn-new', name: 'zeek-lab', connector_type: 'zeek' }))
      const dialog = await openAdd()
      fireEvent.click(within(dialog).getByRole('button', { name: 'Zeek' }))
      fireEvent.change(within(dialog).getByLabelText('Name'), { target: { value: 'zeek-lab' } })
      fireEvent.change(within(dialog).getByLabelText('Log types'), { target: { value: 'conn, dns' } })
      fireEvent.click(within(dialog).getByRole('button', { name: 'Add source' }))
      await waitFor(() => expect(api.create).toHaveBeenCalledWith({
        name: 'zeek-lab', connector_type: 'zeek', config: { log_types: ['conn', 'dns'] }, enabled: true,
      }))
    })

    it('rejects a port that is not a whole number', async () => {
      const dialog = await openAdd()
      fireEvent.click(within(dialog).getByRole('button', { name: 'Syslog' }))
      fireEvent.change(within(dialog).getByLabelText('Name'), { target: { value: 'fw' } })
      fireEvent.change(within(dialog).getByLabelText('UDP port'), { target: { value: 'abc' } })
      fireEvent.click(within(dialog).getByRole('button', { name: 'Add source' }))
      expect(within(dialog).getByRole('alert')).toHaveTextContent('Enter a whole number above zero: UDP port')
      expect(api.create).not.toHaveBeenCalled()
    })

    it('creates a generic webhook source with a generated token', async () => {
      api.create.mockResolvedValue(makeConnector({ id: 'conn-new', name: 'hook-2', connector_type: 'generic', status: 'inactive' }))
      const dialog = await openAdd()
      fireEvent.click(within(dialog).getByRole('button', { name: 'Generic webhook' }))
      fireEvent.change(within(dialog).getByLabelText('Name'), { target: { value: 'hook-2' } })
      fireEvent.click(within(dialog).getByRole('button', { name: 'Generate' }))
      fireEvent.click(within(dialog).getByRole('button', { name: 'Add source' }))
      await waitFor(() => expect(api.create).toHaveBeenCalledTimes(1))
      const body = api.create.mock.calls[0][0]
      expect(body).toMatchObject({ name: 'hook-2', connector_type: 'generic', enabled: true })
      expect(body.config.webhook_token).toMatch(/^[0-9a-f]{48}$/)
    })

    it('shows the server message when adding fails', async () => {
      api.create.mockRejectedValue({ response: { data: { detail: [{ msg: 'Value error, Unknown connector type' }] } } })
      const dialog = await openAdd()
      fireEvent.click(within(dialog).getByRole('button', { name: 'Syslog' }))
      fireEvent.change(within(dialog).getByLabelText('Name'), { target: { value: 'fw' } })
      fireEvent.click(within(dialog).getByRole('button', { name: 'Add source' }))
      expect(await within(dialog).findByText('Value error, Unknown connector type')).toBeInTheDocument()
      expect(notifications()[0]).toMatchObject({ type: 'error', title: 'Add failed' })
    })

    it('sends only the changed config keys when editing', async () => {
      api.update.mockResolvedValue(WAZUH)
      await renderLoaded()
      fireEvent.click(screen.getByTitle('Edit wazuh-prod'))
      const dialog = await screen.findByRole('dialog')
      expect(within(dialog).queryByLabelText('Name')).not.toBeInTheDocument()
      fireEvent.change(within(dialog).getByLabelText(/Password/), { target: { value: 'rotated' } })
      fireEvent.click(within(dialog).getByRole('button', { name: 'Save changes' }))
      await waitFor(() => expect(api.update).toHaveBeenCalledWith('conn-wazuh', { enabled: true, config: { password: 'rotated' } }))
    })

    it('sends no config when nothing was filled in while editing', async () => {
      api.update.mockResolvedValue({ ...SYSLOG, enabled: true })
      await renderLoaded()
      fireEvent.click(screen.getByTitle('Edit fw-syslog'))
      const dialog = await screen.findByRole('dialog')
      fireEvent.click(within(dialog).getByRole('switch', { name: 'Enabled' }))
      fireEvent.click(within(dialog).getByRole('button', { name: 'Save changes' }))
      await waitFor(() => expect(api.update).toHaveBeenCalledWith('conn-syslog', { enabled: true }))
    })
  })

  describe('send a test event', () => {
    it('shows the ingest endpoint and its two headers', async () => {
      await renderLoaded()
      const command = screen.getByText(/curl -X POST/)
      expect(command).toHaveTextContent('/api/v1/ingest')
      expect(command).toHaveTextContent('X-MxTac-Source: my-webhook')
      expect(command).toHaveTextContent('X-MxTac-Token: <webhook token>')
    })

    it('asks for a generic webhook source when there is none', async () => {
      api.list.mockResolvedValue([WAZUH])
      await renderLoaded()
      expect(screen.getByText(/Add a generic webhook source first/)).toBeInTheDocument()
      expect(screen.queryByRole('button', { name: 'Send test event' })).not.toBeInTheDocument()
    })

    it('sends a test event as the generic source with the entered token', async () => {
      sendMock.mockResolvedValue({ accepted: 1, rejected: 0 })
      await renderLoaded()
      const send = screen.getByRole('button', { name: 'Send test event' })
      expect(send).toBeDisabled()
      fireEvent.change(screen.getByLabelText('Webhook token for my-webhook'), { target: { value: 'tok-123' } })
      fireEvent.click(send)
      await waitFor(() => expect(sendMock).toHaveBeenCalledTimes(1))
      expect(sendMock).toHaveBeenCalledWith('my-webhook', 'tok-123', expect.objectContaining({ event_type: 'test' }))
      await waitFor(() => expect(notifications()[0]).toMatchObject({ type: 'success', title: 'Test event accepted' }))
    })

    it('reports a rejected token', async () => {
      sendMock.mockRejectedValue({ response: { data: { detail: 'Invalid webhook token' } } })
      await renderLoaded()
      fireEvent.change(screen.getByLabelText('Webhook token for my-webhook'), { target: { value: 'wrong' } })
      fireEvent.click(screen.getByRole('button', { name: 'Send test event' }))
      await waitFor(() => expect(notifications()).toHaveLength(1))
      expect(notifications()[0]).toMatchObject({ type: 'error', message: 'Invalid webhook token' })
    })
  })
})
