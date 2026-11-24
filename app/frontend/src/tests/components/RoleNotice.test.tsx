// vi.mock is hoisted before imports
vi.mock('../../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../lib/api')>()),
  rulesApi: { list: vi.fn(), stats: vi.fn() },
  connectorsApi: { list: vi.fn() },
}))

vi.mock('../../hooks/useAlertStream', () => ({ useAlertStream: () => 'connected' }))

import { render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactElement } from 'react'
import { RulesPage } from '../../components/features/rules/RulesPage'
import { SourcesPage } from '../../components/features/sources/SourcesPage'
import { connectorsApi, rulesApi } from '../../lib/api'
import { canManageSources, canReadRules } from '../../lib/roles'
import { useAuthStore } from '../../stores/authStore'

function renderPage(page: ReactElement) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{page}</MemoryRouter>
    </QueryClientProvider>,
  )
}

const signInAs = (role: string) => useAuthStore.setState({ user: { email: `${role}@mxtac.local`, role } })

describe('pages a role may not open', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(rulesApi.list).mockResolvedValue([])
    vi.mocked(rulesApi.stats).mockRejectedValue(new Error('not needed'))
    vi.mocked(connectorsApi.list).mockResolvedValue([])
  })

  afterEach(() => {
    useAuthStore.setState({ user: null })
  })

  it('mirrors the backend permission matrix', () => {
    // rules:read is hunter, engineer, admin; connectors:read is engineer, admin (core/rbac.py).
    expect(['viewer', 'analyst', 'hunter', 'engineer', 'admin'].filter(canReadRules)).toEqual(['hunter', 'engineer', 'admin'])
    expect(['viewer', 'analyst', 'hunter', 'engineer', 'admin'].filter(canManageSources)).toEqual(['engineer', 'admin'])
    expect(canReadRules(undefined)).toBe(false)
    expect(canManageSources(undefined)).toBe(false)
  })

  it.each(['viewer', 'analyst'])('tells the %s role why Sigma rules are closed, without a failed request', (role) => {
    signInAs(role)
    renderPage(<RulesPage />)
    expect(screen.getByRole('heading', { level: 1, name: 'Sigma rules' })).toBeInTheDocument()
    expect(screen.getByText('Sigma rules need the hunter role')).toBeInTheDocument()
    expect(screen.queryByText('Could not load rules.')).not.toBeInTheDocument()
    expect(rulesApi.list).not.toHaveBeenCalled()
    expect(rulesApi.stats).not.toHaveBeenCalled()
  })

  it('opens Sigma rules for the hunter role', async () => {
    signInAs('hunter')
    renderPage(<RulesPage />)
    expect(screen.queryByText('Sigma rules need the hunter role')).not.toBeInTheDocument()
    expect(rulesApi.list).toHaveBeenCalled()
  })

  it.each(['viewer', 'analyst', 'hunter'])('tells the %s role why Data sources is closed, without controls', (role) => {
    signInAs(role)
    renderPage(<SourcesPage />)
    expect(screen.getByRole('heading', { level: 1, name: 'Data sources' })).toBeInTheDocument()
    expect(screen.getByText('Data sources need the engineer role')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Add source/ })).not.toBeInTheDocument()
    expect(connectorsApi.list).not.toHaveBeenCalled()
  })

  it('opens Data sources for the engineer role', async () => {
    signInAs('engineer')
    renderPage(<SourcesPage />)
    expect(await screen.findByText('No data sources yet')).toBeInTheDocument()
    expect(connectorsApi.list).toHaveBeenCalled()
  })
})
