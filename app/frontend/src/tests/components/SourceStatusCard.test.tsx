import { render, screen, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, it, expect } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { SourceStatusCard } from '../../components/features/overview/SourceStatusCard'
import { useAuthStore } from '../../stores/authStore'
import type { IntegrationStatus } from '../../types/api'

const sources: IntegrationStatus[] = [
  { id: 'wazuh', name: 'Wazuh', status: 'connected', metric: '1,204 events/min', detail: 'Last event 12 s ago' },
  { id: 'zeek', name: 'Zeek', status: 'warning', metric: 'No events for 2 h' },
  { id: 'suricata', name: 'Suricata', status: 'disabled', metric: 'Disabled' },
]

function renderCard(data: IntegrationStatus[] = sources) {
  return render(
    <MemoryRouter>
      <SourceStatusCard data={data} />
    </MemoryRouter>,
  )
}

describe('SourceStatusCard', () => {
  beforeEach(() => {
    useAuthStore.setState({ user: { email: 'engineer@mxtac.local', role: 'engineer' } })
  })

  afterEach(() => {
    useAuthStore.setState({ user: null })
  })

  it('shows the heading and a link to manage sources', () => {
    renderCard()
    expect(screen.getByRole('heading', { name: 'Data sources' })).toBeInTheDocument()
    expect(screen.getByText('Connector health')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Manage' })).toHaveAttribute('href', '/sources')
  })

  it('lists each source with its name and metric', () => {
    renderCard()
    const items = screen.getAllByRole('listitem')
    expect(items).toHaveLength(3)
    expect(within(items[0]).getByText('Wazuh')).toBeInTheDocument()
    expect(within(items[0]).getByText('1,204 events/min')).toBeInTheDocument()
    expect(within(items[1]).getByText('Zeek')).toBeInTheDocument()
    expect(within(items[1]).getByText('No events for 2 h')).toBeInTheDocument()
    expect(within(items[2]).getByText('Suricata')).toBeInTheDocument()
  })

  it('exposes the detail as a tooltip only when there is one', () => {
    renderCard()
    const [wazuh, zeek] = screen.getAllByRole('listitem')
    expect(wazuh).toHaveAttribute('title', 'Last event 12 s ago')
    expect(zeek).not.toHaveAttribute('title')
  })

  it('renders a source with an unknown status', () => {
    renderCard([{ id: 'x', name: 'Custom feed', status: 'unknown' as IntegrationStatus['status'], metric: 'n/a' }])
    expect(screen.getByText('Custom feed')).toBeInTheDocument()
  })

  it('shows an empty state with a link to add a source when nothing is connected', () => {
    renderCard([])
    expect(screen.getByText('No data sources connected')).toBeInTheDocument()
    expect(screen.getByText(/Connect Wazuh, Zeek, Suricata, a syslog feed or a webhook/)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Add a source' })).toHaveAttribute('href', '/sources')
    expect(screen.queryByRole('list')).not.toBeInTheDocument()
  })

  it.each(['viewer', 'analyst', 'hunter'])('offers no link to the Sources page to the %s role', (role) => {
    useAuthStore.setState({ user: { email: `${role}@mxtac.local`, role } })
    const { unmount } = renderCard()
    expect(screen.getByText('Wazuh')).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Manage' })).not.toBeInTheDocument()
    unmount()

    renderCard([])
    expect(screen.getByText('An engineer or admin account can connect a source.')).toBeInTheDocument()
    expect(screen.queryByRole('link')).not.toBeInTheDocument()
  })
})
