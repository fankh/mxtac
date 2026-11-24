// vi.mock is hoisted before imports — declare all module mocks first.

vi.mock('../../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof ApiModule>()),
  eventsApi: {
    search: vi.fn(),
    aggregate: vi.fn(),
    entity: vi.fn(),
    queryDsl: vi.fn(),
    exportCsv: vi.fn(),
    get: vi.fn(),
  },
  savedQueriesApi: {
    list: vi.fn(),
    create: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
  },
}))

vi.mock('../../components/layout/TopBar', () => ({
  TopBar: ({ crumb, actions }: { crumb: string; actions?: ReactNode }) => (
    <header data-testid="topbar">
      <h1>{crumb}</h1>
      {actions}
    </header>
  ),
}))

import type { ReactNode } from 'react'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, it, expect, vi, beforeAll, beforeEach, afterEach } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, useLocation } from 'react-router-dom'
import { HuntPage } from '../../components/features/hunt/HuntPage'
import { buildSearchRequest, eventLink, newFilterRow, toFilterRows } from '../../components/features/hunt/huntUtils'
import type * as ApiModule from '../../lib/api'
import { eventsApi, savedQueriesApi } from '../../lib/api'
import { useAuthStore } from '../../stores/authStore'
import { useUIStore } from '../../stores/uiStore'
import type {
  AggregationRequest, EntityTimeline, EventItem, SavedQuery, SearchResponse,
} from '../../types/api'

const mockEvents = vi.mocked(eventsApi)
const mockSaved = vi.mocked(savedQueriesApi)

// ---------------------------------------------------------------------------
// Fixtures (shapes follow app/backend/app/api/v1/endpoints/events.py and saved_queries.py)
// ---------------------------------------------------------------------------

const EVENT_A: EventItem = {
  id: '1aa9e407-9bd6-451f-a144-e23eaec6c792',
  event_uid: 'evt-a',
  time: '2026-02-19T08:30:00+00:00',
  class_name: 'Process Activity',
  class_uid: 1007,
  severity_id: 4,
  src_ip: '10.0.0.5',
  dst_ip: '10.0.0.9',
  hostname: 'WIN-DC01',
  username: 'svc-backup',
  process_hash: undefined,
  source: 'wazuh',
  summary: 'powershell.exe spawned by winword.exe',
}

const EVENT_B: EventItem = {
  id: 'e86745ef-360e-4e56-b523-053d08dee0f6',
  time: '2026-02-19T08:10:00+00:00',
  class_name: 'Network Activity',
  class_uid: 4001,
  severity_id: 2,
  src_ip: '10.0.0.7',
  hostname: 'LNX-WEB02',
  source: 'zeek',
  summary: 'Outbound connection to a rare port',
}

const SEARCH_RESPONSE: SearchResponse = {
  total: 2,
  items: [EVENT_A, EVENT_B],
  from_: 0,
  size: 50,
  backend: 'postgres',
}

const SAVED: SavedQuery = {
  id: '92116ed0-eb10-4222-b47a-a08d8b56398c',
  name: 'Office spawning shells',
  description: 'Word or Excel starting PowerShell',
  query: 'powershell',
  filters: [{ field: 'hostname', operator: 'contains', value: 'WIN' }],
  time_from: 'now-7d',
  time_to: 'now',
  created_by: 'hunter@mxtac.local',
  created_at: '2026-02-18T10:00:00+00:00',
  updated_at: '2026-02-18T10:00:00+00:00',
}

const ENTITY: EntityTimeline = {
  entity_type: 'host',
  entity_value: 'WIN-DC01',
  total: 1,
  events: [EVENT_A],
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Shows the address the router is at, so tests can read the query string. */
function Address() {
  const { pathname, search } = useLocation()
  return <output data-testid="address">{pathname}{search}</output>
}

function renderPage(address = '/hunt') {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return render(
    <MemoryRouter initialEntries={[address]}>
      <QueryClientProvider client={queryClient}>
        <HuntPage />
        <Address />
      </QueryClientProvider>
    </MemoryRouter>,
  )
}

async function renderLoaded() {
  const user = userEvent.setup()
  renderPage()
  await screen.findByText('powershell.exe spawned by winword.exe')
  return user
}

beforeAll(() => {
  // Recharts' ResponsiveContainer needs ResizeObserver, which jsdom lacks.
  vi.stubGlobal(
    'ResizeObserver',
    vi.fn().mockImplementation(() => ({ observe: vi.fn(), unobserve: vi.fn(), disconnect: vi.fn() })),
  )
})

beforeEach(() => {
  vi.clearAllMocks()
  useAuthStore.setState({ user: { email: 'hunter@mxtac.local', role: 'hunter' } })
  useUIStore.setState({ notifications: [] })

  mockEvents.search.mockResolvedValue(SEARCH_RESPONSE)
  mockEvents.aggregate.mockImplementation((body: AggregationRequest = {}) =>
    Promise.resolve(
      body.agg_type === 'date_histogram'
        ? { agg_type: 'date_histogram', interval: body.interval, buckets: [{ key: '2026-02-19T08:00:00+00:00', count: 2 }] }
        : { field: body.field, buckets: [{ key: 'wazuh', count: 7 }, { key: 'zeek', count: 3 }] },
    ),
  )
  mockEvents.queryDsl.mockResolvedValue({ lucene: 'time:[now-24h TO now]' })
  mockEvents.get.mockResolvedValue(EVENT_A)
  mockEvents.entity.mockResolvedValue(ENTITY)
  mockSaved.list.mockResolvedValue({ items: [SAVED], total: 1 })
})

afterEach(() => {
  useAuthStore.setState({ user: null })
})

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('HuntPage', () => {
  describe('search', () => {
    it('runs a search for the last 24 hours on load, with the backend field names', async () => {
      await renderLoaded()
      expect(mockEvents.search).toHaveBeenCalledWith({
        query: undefined,
        filters: [],
        time_from: 'now-24h',
        time_to: 'now',
        size: 50,
        from_: 0,
      })
    })

    it('lists the returned events with the total and the search backend', async () => {
      await renderLoaded()
      expect(screen.getByText('Outbound connection to a rare port')).toBeInTheDocument()
      expect(screen.getByText('WIN-DC01')).toBeInTheDocument()
      expect(screen.getByText('High')).toBeInTheDocument()
      expect(screen.getByText('2 events · PostgreSQL')).toBeInTheDocument()
    })

    it('sends the typed query when Search is clicked', async () => {
      const user = await renderLoaded()
      await user.type(screen.getByLabelText('Search query'), 'powershell')
      await user.click(screen.getByRole('button', { name: 'Search' }))
      await waitFor(() =>
        expect(mockEvents.search).toHaveBeenLastCalledWith(
          expect.objectContaining({ query: 'powershell', time_from: 'now-24h', from_: 0 }),
        ),
      )
    })

    it('clears the query with Escape and with the clear button', async () => {
      const user = await renderLoaded()
      const input = screen.getByLabelText('Search query')
      await user.type(input, 'abc')
      await user.keyboard('{Escape}')
      expect(input).toHaveValue('')

      await user.type(input, 'abc')
      await user.click(screen.getByTitle('Clear search'))
      expect(input).toHaveValue('')
    })

    it('sends an added filter row with the search', async () => {
      const user = await renderLoaded()
      await user.click(screen.getByRole('button', { name: 'Add filter' }))
      await user.type(screen.getByLabelText('Filter value'), 'WIN-DC01')
      await user.click(screen.getByRole('button', { name: 'Search' }))
      await waitFor(() =>
        expect(mockEvents.search).toHaveBeenLastCalledWith(
          expect.objectContaining({ filters: [{ field: 'hostname', operator: 'eq', value: 'WIN-DC01' }] }),
        ),
      )
    })

    it('removes a filter row', async () => {
      const user = await renderLoaded()
      await user.click(screen.getByRole('button', { name: 'Add filter' }))
      expect(screen.getAllByTestId('filter-row')).toHaveLength(1)
      await user.click(screen.getByTitle('Remove filter'))
      expect(screen.queryByTestId('filter-row')).not.toBeInTheDocument()
    })

    it('shows the Lucene form of the search from /events/query-dsl', async () => {
      await renderLoaded()
      expect(await screen.findByTestId('lucene-query')).toHaveTextContent('time:[now-24h TO now]')
      expect(mockEvents.queryDsl).toHaveBeenCalledWith(expect.objectContaining({ time_from: 'now-24h' }))
    })

    it('shows an empty state when nothing matches', async () => {
      mockEvents.search.mockResolvedValue({ ...SEARCH_RESPONSE, total: 0, items: [] })
      renderPage()
      expect(await screen.findByText('No events match this search')).toBeInTheDocument()
    })

    it('shows an error with a retry button when the search fails', async () => {
      mockEvents.search.mockRejectedValueOnce(new Error('boom'))
      const user = userEvent.setup()
      renderPage()
      expect(await screen.findByText(/The search failed/)).toBeInTheDocument()
      const resultsCard = screen.getByText(/The search failed/).parentElement as HTMLElement
      await user.click(within(resultsCard).getByRole('button', { name: 'Retry' }))
      expect(await screen.findByText('powershell.exe spawned by winword.exe')).toBeInTheDocument()
    })

    it('requests the next page with from_ set to the page offset', async () => {
      mockEvents.search.mockResolvedValue({ ...SEARCH_RESPONSE, total: 120 })
      const user = await renderLoaded()
      await user.click(screen.getByTitle('Next page'))
      await waitFor(() =>
        expect(mockEvents.search).toHaveBeenLastCalledWith(expect.objectContaining({ from_: 50, size: 50 })),
      )
    })
  })

  describe('aggregations', () => {
    it('requests a date histogram and a terms aggregation for the time range', async () => {
      await renderLoaded()
      expect(mockEvents.aggregate).toHaveBeenCalledWith({
        agg_type: 'date_histogram', interval: '1h', time_from: 'now-24h', time_to: 'now',
      })
      expect(mockEvents.aggregate).toHaveBeenCalledWith({
        agg_type: 'terms', field: 'source', size: 8, time_from: 'now-24h', time_to: 'now',
      })
    })

    it('adds a filter and searches again when a top value is clicked', async () => {
      const user = await renderLoaded()
      await user.click(await screen.findByTitle('Filter by zeek'))
      await waitFor(() =>
        expect(mockEvents.search).toHaveBeenLastCalledWith(
          expect.objectContaining({ filters: [{ field: 'source', operator: 'eq', value: 'zeek' }] }),
        ),
      )
    })
  })

  describe('event detail', () => {
    it('opens the event in a side panel and loads it by ID', async () => {
      const user = await renderLoaded()
      await user.click(screen.getByText('powershell.exe spawned by winword.exe'))
      const dialog = await screen.findByRole('dialog')
      expect(within(dialog).getByText('Raw event')).toBeInTheDocument()
      expect(within(dialog).getByText(EVENT_A.id)).toBeInTheDocument()
      expect(mockEvents.get).toHaveBeenCalledWith(EVENT_A.id)
    })

    it('keeps showing the search row when GET /events/{id} fails', async () => {
      mockEvents.get.mockRejectedValue(new Error('404'))
      const user = await renderLoaded()
      await user.click(screen.getByText('powershell.exe spawned by winword.exe'))
      const dialog = await screen.findByRole('dialog')
      await waitFor(() => expect(mockEvents.get).toHaveBeenCalled())
      expect(within(dialog).getByText('Process Activity')).toBeInTheDocument()
    })

    it('pivots to the entity timeline with the backend entity type', async () => {
      const user = await renderLoaded()
      await user.click(screen.getByText('powershell.exe spawned by winword.exe'))
      const dialog = await screen.findByRole('dialog')
      await user.click(within(dialog).getByTitle('Show timeline for host'))
      expect(await within(dialog).findByText(/Events for this host/)).toBeInTheDocument()
      expect(mockEvents.entity).toHaveBeenCalledWith('host', 'WIN-DC01', 'now-24h')

      await user.click(within(dialog).getByRole('button', { name: 'Back to event' }))
      expect(within(dialog).getByText('Raw event')).toBeInTheDocument()
    })
  })

  describe('link to one event (/hunt?event=<id>)', () => {
    // An event that is not part of the search results, as when a detection links to it.
    const LINKED: EventItem = {
      id: '3f6c1a52-7a0e-4c53-9d8b-0c1d2e3f4a5b',
      time: '2026-01-05T03:12:00+00:00',
      class_name: 'Authentication',
      hostname: 'web01',
      source: 'syslog',
      summary: 'Failed password for root from 203.0.113.5',
    }

    it('builds the address of an event', () => {
      expect(eventLink(LINKED.id)).toBe(`/hunt?event=${LINKED.id}`)
      expect(eventLink('a b&c')).toBe('/hunt?event=a%20b%26c')
    })

    it('opens the detail of the linked event, also when the search does not list it', async () => {
      mockEvents.get.mockResolvedValue(LINKED)
      renderPage(eventLink(LINKED.id))

      const dialog = await screen.findByRole('dialog')
      expect(mockEvents.get).toHaveBeenCalledWith(LINKED.id)
      expect(within(dialog).getByText('Authentication')).toBeInTheDocument()
      expect(within(dialog).getByText(LINKED.id)).toBeInTheDocument()
      expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    })

    it('removes the event from the address when the detail is closed', async () => {
      mockEvents.get.mockResolvedValue(LINKED)
      const user = userEvent.setup()
      renderPage(eventLink(LINKED.id))
      await screen.findByRole('dialog')

      await user.keyboard('{Escape}')

      await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
      expect(screen.getByTestId('address')).toHaveTextContent(/^\/hunt$/)
    })

    it('puts the event of a clicked row into the address, so the page can be shared', async () => {
      const user = await renderLoaded()
      expect(screen.getByTestId('address')).toHaveTextContent(/^\/hunt$/)

      await user.click(screen.getByText('powershell.exe spawned by winword.exe'))

      await screen.findByRole('dialog')
      expect(screen.getByTestId('address')).toHaveTextContent(`/hunt?event=${EVENT_A.id}`)
    })

    it('keeps other query parameters of the address', async () => {
      mockEvents.get.mockResolvedValue(LINKED)
      const user = userEvent.setup()
      renderPage(`/hunt?from=detection&event=${LINKED.id}`)
      await screen.findByRole('dialog')

      await user.keyboard('{Escape}')

      await waitFor(() => expect(screen.getByTestId('address')).toHaveTextContent(/^\/hunt\?from=detection$/))
    })

    it('says so when the linked event cannot be loaded, and can be dismissed', async () => {
      mockEvents.get.mockRejectedValue({ response: { status: 404, data: { detail: 'Event not found' } } })
      const user = userEvent.setup()
      renderPage(eventLink(LINKED.id))

      const alert = await screen.findByRole('alert')
      expect(alert).toHaveTextContent(`Could not open event ${LINKED.id}: Event not found`)
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
      // The search itself still works
      expect(await screen.findByText('powershell.exe spawned by winword.exe')).toBeInTheDocument()

      await user.click(within(alert).getByTitle('Dismiss'))
      expect(screen.queryByRole('alert')).not.toBeInTheDocument()
      expect(screen.getByTestId('address')).toHaveTextContent(/^\/hunt$/)
    })

    it('closes the detail and the address when a value is added as a filter', async () => {
      const user = await renderLoaded()
      await user.click(screen.getByText('powershell.exe spawned by winword.exe'))
      const dialog = await screen.findByRole('dialog')

      await user.click(within(dialog).getAllByTitle(/^Filter by/)[0])

      await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
      expect(screen.getByTestId('address')).toHaveTextContent(/^\/hunt$/)
    })
  })

  describe('saved queries', () => {
    it('lists the saved queries of the user', async () => {
      await renderLoaded()
      expect(await screen.findByText('Office spawning shells')).toBeInTheDocument()
      expect(screen.getByText('Word or Excel starting PowerShell')).toBeInTheDocument()
    })

    it('loads a saved query into the form and runs it', async () => {
      const user = await renderLoaded()
      await user.click(await screen.findByTitle('Run Office spawning shells'))
      await waitFor(() =>
        expect(mockEvents.search).toHaveBeenLastCalledWith(
          expect.objectContaining({
            query: 'powershell',
            filters: [{ field: 'hostname', operator: 'contains', value: 'WIN' }],
            time_from: 'now-7d',
          }),
        ),
      )
      expect(screen.getByLabelText('Search query')).toHaveValue('powershell')
      expect(screen.getByLabelText('Filter value')).toHaveValue('WIN')
    })

    it('saves the current search under a name', async () => {
      mockSaved.create.mockResolvedValue({ ...SAVED, id: 'b48199ff-592d-4af1-813e-0e91dcc8b93f', name: 'My hunt' })
      const user = await renderLoaded()
      await user.type(screen.getByLabelText('Search query'), 'mimikatz')
      await user.click(screen.getByRole('button', { name: 'Save query' }))
      const dialog = await screen.findByRole('dialog')
      await user.type(within(dialog).getByLabelText('Name'), 'My hunt')
      await user.click(within(dialog).getByRole('button', { name: 'Save query' }))
      await waitFor(() =>
        expect(mockSaved.create).toHaveBeenCalledWith({
          name: 'My hunt',
          description: undefined,
          query: 'mimikatz',
          filters: [],
          time_from: 'now-24h',
          time_to: 'now',
        }),
      )
      await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    })

    it('does not submit the save dialog without a name', async () => {
      const user = await renderLoaded()
      await user.click(screen.getByRole('button', { name: 'Save query' }))
      const dialog = await screen.findByRole('dialog')
      expect(within(dialog).getByRole('button', { name: 'Save query' })).toBeDisabled()
    })

    it('reports a failed save as an error notification', async () => {
      mockSaved.create.mockRejectedValue({ response: { data: { detail: 'Name already used' } } })
      const user = await renderLoaded()
      await user.click(screen.getByRole('button', { name: 'Save query' }))
      const dialog = await screen.findByRole('dialog')
      await user.type(within(dialog).getByLabelText('Name'), 'Dup')
      await user.click(within(dialog).getByRole('button', { name: 'Save query' }))
      await waitFor(() =>
        expect(useUIStore.getState().notifications).toEqual([
          expect.objectContaining({ type: 'error', title: 'Could not save the query', message: 'Name already used' }),
        ]),
      )
    })

    it('renames a saved query without touching its stored search', async () => {
      mockSaved.update.mockResolvedValue({ ...SAVED, name: 'Renamed' })
      const user = await renderLoaded()
      await user.click(await screen.findByTitle('Edit Office spawning shells'))
      const dialog = await screen.findByRole('dialog')
      const name = within(dialog).getByLabelText('Name')
      expect(name).toHaveValue('Office spawning shells')
      await user.clear(name)
      await user.type(name, 'Renamed')
      await user.click(within(dialog).getByRole('button', { name: 'Save changes' }))
      await waitFor(() =>
        expect(mockSaved.update).toHaveBeenCalledWith(SAVED.id, {
          name: 'Renamed',
          description: 'Word or Excel starting PowerShell',
        }),
      )
    })

    it('deletes a saved query after confirmation', async () => {
      mockSaved.delete.mockResolvedValue(undefined)
      const user = await renderLoaded()
      await user.click(await screen.findByTitle('Delete Office spawning shells'))
      const dialog = await screen.findByRole('dialog')
      expect(mockSaved.delete).not.toHaveBeenCalled()
      await user.click(within(dialog).getByRole('button', { name: 'Delete' }))
      await waitFor(() => expect(mockSaved.delete).toHaveBeenCalledWith(SAVED.id))
    })

    it('reports a failed delete as an error notification', async () => {
      mockSaved.delete.mockRejectedValue(new Error('Network Error'))
      const user = await renderLoaded()
      await user.click(await screen.findByTitle('Delete Office spawning shells'))
      const dialog = await screen.findByRole('dialog')
      await user.click(within(dialog).getByRole('button', { name: 'Delete' }))
      await waitFor(() =>
        expect(useUIStore.getState().notifications).toEqual([
          expect.objectContaining({ type: 'error', title: 'Could not delete the saved query' }),
        ]),
      )
    })
  })

  describe('export', () => {
    it('exports the search that was run as CSV', async () => {
      const createObjectURL = vi.fn(() => 'blob:mock')
      const revokeObjectURL = vi.fn()
      vi.stubGlobal('URL', Object.assign(URL, { createObjectURL, revokeObjectURL }))
      const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
      const blob = new Blob(['id,time\n'], { type: 'text/csv' })
      mockEvents.exportCsv.mockResolvedValue(blob)

      const user = await renderLoaded()
      await user.click(screen.getByRole('button', { name: 'Export CSV' }))
      await waitFor(() => expect(createObjectURL).toHaveBeenCalledWith(blob))
      expect(mockEvents.exportCsv).toHaveBeenCalledWith({
        query: undefined, filters: [], time_from: 'now-24h', time_to: 'now',
      })
      expect(click).toHaveBeenCalled()
      click.mockRestore()
    })

    it('reports a failed export as an error notification', async () => {
      mockEvents.exportCsv.mockRejectedValue(new Error('Network Error'))
      const user = await renderLoaded()
      await user.click(screen.getByRole('button', { name: 'Export CSV' }))
      await waitFor(() =>
        expect(useUIStore.getState().notifications).toEqual([
          expect.objectContaining({ type: 'error', title: 'Could not export events' }),
        ]),
      )
    })
  })

  describe('access', () => {
    it('shows a notice and calls nothing for a role without events:search', () => {
      useAuthStore.setState({ user: { email: 'analyst@mxtac.local', role: 'analyst' } })
      renderPage()
      expect(screen.getByText('Hunting needs the hunter role')).toBeInTheDocument()
      expect(mockEvents.search).not.toHaveBeenCalled()
      expect(mockSaved.list).not.toHaveBeenCalled()
    })
  })
})

describe('buildSearchRequest', () => {
  it('drops empty filter rows and trims the query', () => {
    const req = buildSearchRequest('  ssh  ', [newFilterRow({ value: '   ' })], 'now-1h')
    expect(req).toEqual({ query: 'ssh', filters: [], time_from: 'now-1h', time_to: 'now' })
  })

  it('sends numeric fields as numbers and skips values that are not numbers', () => {
    const req = buildSearchRequest('', [
      newFilterRow({ field: 'severity_id', operator: 'gte', value: '4' }),
      newFilterRow({ field: 'class_uid', operator: 'eq', value: 'abc' }),
    ], 'now-7d')
    expect(req.filters).toEqual([{ field: 'severity_id', operator: 'gte', value: 4 }])
  })

  it('round-trips saved filters into rows, defaulting an unknown operator to eq', () => {
    const rows = toFilterRows([
      { field: 'src_ip', operator: 'contains', value: '10.0' },
      { field: 'severity_id', operator: 'between', value: 3 },
    ])
    expect(rows.map(({ field, operator, value }) => ({ field, operator, value }))).toEqual([
      { field: 'src_ip', operator: 'contains', value: '10.0' },
      { field: 'severity_id', operator: 'eq', value: '3' },
    ])
  })
})
