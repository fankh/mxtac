import type { ReactNode } from 'react'
import { render, renderHook, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { http, HttpResponse } from 'msw'
import { server } from '../mocks/server'
import { DetectionPanel } from '../../components/features/detections/DetectionPanel'
import { techniqueLabel } from '../../components/features/detections/utils'
import { LoginPage } from '../../components/features/auth/LoginPage'
import { ProtectedRoute } from '../../components/shared/ProtectedRoute'
import { AttackHeatmap } from '../../components/features/overview/AttackHeatmap'
import { shortTechniqueName } from '../../components/features/coverage/coverageUtils'
import { useTechniqueNames } from '../../hooks/useTechniqueNames'
import { useAuthStore } from '../../stores/authStore'
import type { Detection, HeatRow } from '../../types/api'

// Technique names come from GET /attack/techniques and the event link from detection.event_id.
// Both run against the MSW handlers in tests/mocks/handlers.ts.

const EVENT_ID = '3f6c1a52-7a0e-4c53-9d8b-0c1d2e3f4a5b'

function makeDetection(overrides: Partial<Detection> = {}): Detection {
  return {
    id: '8a1f0f0e-2f4b-4a51-9b9d-1b1c8f4f7c55',
    score: 7.4,
    severity: 'high',
    technique_id: 'T1059.004',
    technique_name: 'Command and Scripting Interpreter: Unix Shell',
    name: 'Interactive Bash Reverse Shell',
    host: 'app02',
    tactic: 'Execution',
    tactic_id: 'TA0002',
    status: 'active',
    time: '2026-02-19T08:30:00Z',
    event_id: EVENT_ID,
    related_technique_ids: ['T1003.001', 'T9999'],
    ...overrides,
  }
}

function Address() {
  const { pathname, search } = useLocation()
  return <output data-testid="address">{pathname}{search}</output>
}

function providers(address = '/detections') {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: ReactNode }) => (
    <MemoryRouter initialEntries={[address]}>
      <QueryClientProvider client={client}>{children}</QueryClientProvider>
    </MemoryRouter>
  )
}

function renderPanel(detection: Detection, role = 'hunter') {
  useAuthStore.setState({ user: { email: `${role}@mxtac.local`, role }, isAuthenticated: true })
  return render(
    <>
      <DetectionPanel detection={detection} onClose={() => {}} />
      <Address />
    </>,
    { wrapper: providers() },
  )
}

beforeEach(() => {
  localStorage.clear()
  sessionStorage.clear()
  useAuthStore.setState({
    user: null, token: null, isAuthenticated: false, isLoading: false, error: null,
    mfaPending: false, mfaToken: null, passwordChangePending: false, passwordChangeToken: null, pendingEmail: null,
  })
})

describe('useTechniqueNames', () => {
  it('answers undefined until the table has arrived, then the name', async () => {
    const { result } = renderHook(() => useTechniqueNames(), { wrapper: providers() })
    expect(result.current('T1059')).toBeUndefined()

    await waitFor(() => expect(result.current('T1059')).toBe('Command and Scripting Interpreter'))
    expect(result.current('T1003.001')).toBe('OS Credential Dumping: LSASS Memory')
  })

  it('ignores case and surrounding space, and knows no name for an unknown ID', async () => {
    const { result } = renderHook(() => useTechniqueNames(), { wrapper: providers() })
    await waitFor(() => expect(result.current(' t1059 ')).toBe('Command and Scripting Interpreter'))
    expect(result.current('T9999')).toBeUndefined()
    expect(result.current('unknown')).toBeUndefined()
  })

  it('asks the backend once for all components that share the query client', async () => {
    let requests = 0
    server.use(
      http.get('/api/v1/attack/techniques', () => {
        requests += 1
        return HttpResponse.json({ attack_version: '20.1', retrieved: '2026-11-25', techniques: { T1059: 'Name' } })
      }),
    )
    const wrapper = providers()
    const first = renderHook(() => useTechniqueNames(), { wrapper })
    await waitFor(() => expect(first.result.current('T1059')).toBe('Name'))
    first.rerender()
    expect(requests).toBe(1)
  })

  it('answers undefined when the table cannot be loaded', async () => {
    let requests = 0
    server.use(
      http.get('/api/v1/attack/techniques', () => {
        requests += 1
        return HttpResponse.json({ detail: 'down' }, { status: 503 })
      }),
    )
    const { result } = renderHook(() => useTechniqueNames(), { wrapper: providers() })
    await waitFor(() => expect(requests).toBeGreaterThan(0))
    expect(result.current('T1059')).toBeUndefined()
  })
})

describe('technique names in the detection views', () => {
  it('techniqueLabel shows the ATT&CK name the backend answers with', () => {
    expect(techniqueLabel(makeDetection())).toBe('Command and Scripting Interpreter: Unix Shell')
  })

  it('techniqueLabel shows nothing when the name only repeats the rule title or the ID', () => {
    expect(techniqueLabel(makeDetection({ technique_name: 'Interactive Bash Reverse Shell' }))).toBe('')
    expect(techniqueLabel(makeDetection({ technique_id: 'T9999', technique_name: 'T9999' }))).toBe('')
  })

  it('the detection sheet shows the technique name next to the ID', async () => {
    renderPanel(makeDetection())
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText('Command and Scripting Interpreter: Unix Shell')).toBeInTheDocument()
  })

  it('related techniques carry their name as a tooltip', async () => {
    renderPanel(makeDetection())
    const dialog = await screen.findByRole('dialog')
    await waitFor(() =>
      expect(within(dialog).getByText('T1003.001')).toHaveAttribute('title', 'OS Credential Dumping: LSASS Memory'))
    expect(within(dialog).getByText('T9999')).not.toHaveAttribute('title')
  })

  it('shortTechniqueName keeps the sub-technique part', () => {
    expect(shortTechniqueName('OS Credential Dumping: LSASS Memory')).toBe('LSASS Memory')
    expect(shortTechniqueName('Brute Force')).toBe('Brute Force')
    expect(shortTechniqueName(undefined)).toBe('')
  })

  it('the Overview heatmap names the technique family in the row and cell tooltips', () => {
    const rows: HeatRow[] = [
      { technique_id: 'T1059', technique_name: 'Command and Scripting Interpreter', row: 0,
        cells: [{ tactic: 'EXEC', covered: 2, total: 9, opacity: 0.3 }] },
      { technique_id: 'T1003', technique_name: null, row: 1,
        cells: [{ tactic: 'EXEC', covered: 0, total: 9, opacity: 0 }] },
    ]
    render(<AttackHeatmap rows={rows} tacticLabels={['EXEC']} />, { wrapper: providers() })

    expect(screen.getByText('T1059')).toHaveAttribute('title', 'T1059 Command and Scripting Interpreter')
    expect(screen.getByTitle('T1059 Command and Scripting Interpreter · EXEC: 2 of 9')).toBeInTheDocument()
    expect(screen.getByText('T1003')).toHaveAttribute('title', 'T1003')
  })
})

describe('"Open event in Hunt" in the detection sheet', () => {
  it('links to Hunt with the event of the detection', async () => {
    renderPanel(makeDetection())
    const link = await screen.findByRole('link', { name: 'Open event in Hunt' })
    expect(link).toHaveAttribute('href', `/hunt?event=${EVENT_ID}`)
  })

  it('navigates inside the application', async () => {
    const user = userEvent.setup()
    renderPanel(makeDetection())
    await user.click(await screen.findByRole('link', { name: 'Open event in Hunt' }))
    expect(screen.getByTestId('address')).toHaveTextContent(`/hunt?event=${EVENT_ID}`)
  })

  it.each(['engineer', 'admin'])('is offered to the %s role', async (role) => {
    renderPanel(makeDetection(), role)
    expect(await screen.findByRole('link', { name: 'Open event in Hunt' })).toBeInTheDocument()
  })

  it.each(['viewer', 'analyst'])('is not offered to the %s role, which cannot search events', async (role) => {
    renderPanel(makeDetection(), role)
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText(EVENT_ID)).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Open event in Hunt' })).not.toBeInTheDocument()
  })

  it('is not offered when the detection has no event, or a value that is not an event ID', async () => {
    const { unmount } = renderPanel(makeDetection({ event_id: null }))
    await screen.findByRole('dialog')
    expect(screen.queryByText('Event ID')).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Open event in Hunt' })).not.toBeInTheDocument()
    unmount()

    renderPanel(makeDetection({ event_id: '4662' }))   // demo data: a Windows event number
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText('4662')).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Open event in Hunt' })).not.toBeInTheDocument()
  })
})

describe('event link and sign-in', () => {
  function renderApp(address: string) {
    return render(
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/*" element={<ProtectedRoute><Address /></ProtectedRoute>} />
      </Routes>,
      { wrapper: providers(address) },
    )
  }

  it('a signed-out visitor of /hunt?event=<id> lands on it after signing in', async () => {
    const user = userEvent.setup()
    renderApp(`/hunt?event=${EVENT_ID}`)

    await user.type(await screen.findByLabelText('Email'), 'analyst@mxtac.local')
    await user.type(screen.getByLabelText('Password'), 'Analyst-Passw0rd')
    await user.click(screen.getByRole('button', { name: 'Sign in' }))

    expect(await screen.findByTestId('address')).toHaveTextContent(`/hunt?event=${EVENT_ID}`)
  })

  it('a visitor whose session ended on /hunt?event=<id> sees the notice and returns to it', async () => {
    // What the API client leaves behind when the refresh is refused (lib/api.ts, endSession)
    sessionStorage.setItem('mxtac-session-ended', '1')
    sessionStorage.setItem('mxtac-return-to', `/hunt?event=${EVENT_ID}`)
    const user = userEvent.setup()
    renderApp('/login')

    expect(screen.getByRole('status')).toHaveTextContent('Your session has ended. Sign in again.')
    await user.type(screen.getByLabelText('Email'), 'analyst@mxtac.local')
    await user.type(screen.getByLabelText('Password'), 'Analyst-Passw0rd')
    await user.click(screen.getByRole('button', { name: 'Sign in' }))

    expect(await screen.findByTestId('address')).toHaveTextContent(`/hunt?event=${EVENT_ID}`)
  })
})
