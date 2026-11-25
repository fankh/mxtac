// vi.mock is hoisted before imports — declare module mocks first.

vi.mock('../../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof ApiModule>()),
  authApi: {},
  detectionsApi: {
    update: vi.fn(),
  },
}))

import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { DetectionPanel } from '../../components/features/detections/DetectionPanel'
import type * as ApiModule from '../../lib/api'
import { detectionsApi } from '../../lib/api'
import { useAuthStore } from '../../stores/authStore'
import { useUIStore } from '../../stores/uiStore'
import type { Detection } from '../../types/api'

const updateMock = vi.mocked(detectionsApi.update)

function makeDetection(overrides: Partial<Detection> = {}): Detection {
  return {
    id: 'det-001',
    score: 9.2,
    severity: 'critical',
    technique_id: 'T1003.001',
    technique_name: 'LSASS Memory',
    name: 'Suspicious LSASS access',
    host: 'WIN-DC01',
    tactic: 'Credential Access',
    tactic_id: 'TA0006',
    status: 'active',
    time: '2026-02-19T08:30:00Z',
    user: 'CORP\\svc-backup',
    process: 'rundll32.exe comsvcs.dll',
    rule_name: 'proc_access_win_lsass',
    log_source: 'wazuh',
    event_id: 'evt-7781',
    occurrence_count: 1204,
    description: 'A process opened LSASS with read access.',
    cvss_v3: 8.8,
    confidence: 92,
    related_technique_ids: ['T1003.002', 'T1558'],
    assigned_to: null,
    priority: null,
    ...overrides,
  }
}

function renderPanel(detection: Detection | null, handlers: { onClose?: () => void; onUpdated?: (d: Detection) => void } = {}) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const invalidate = vi.spyOn(client, 'invalidateQueries')
  const onClose = handlers.onClose ?? vi.fn()
  const view = render(
    <QueryClientProvider client={client}>
      <DetectionPanel detection={detection} onClose={onClose} onUpdated={handlers.onUpdated} />
    </QueryClientProvider>,
  )
  return { ...view, invalidate, onClose }
}

function notifications() {
  return useUIStore.getState().notifications
}

beforeEach(() => {
  vi.clearAllMocks()
  useAuthStore.setState({ user: { email: 'analyst@mxtac.local', role: 'analyst' } })
  useUIStore.setState({ notifications: [] })
})

describe('DetectionPanel', () => {
  describe('content', () => {
    it('renders nothing while no detection is selected', () => {
      renderPanel(null)
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    })

    it('shows the detection as a labelled side panel', () => {
      renderPanel(makeDetection())
      const dialog = screen.getByRole('dialog', { name: 'Suspicious LSASS access' })
      expect(dialog).toHaveTextContent('T1003.001 · Credential Access')
      expect(dialog).toHaveTextContent('A process opened LSASS with read access.')
      expect(dialog).toHaveTextContent('Confidence 92%')
      expect(dialog).toHaveTextContent('CVSS 8.8')
    })

    it('lists the detail fields', () => {
      renderPanel(makeDetection())
      expect(screen.getByText('WIN-DC01')).toBeInTheDocument()
      expect(screen.getByText('CORP\\svc-backup')).toBeInTheDocument()
      expect(screen.getByText('rundll32.exe comsvcs.dll')).toBeInTheDocument()
      expect(screen.getByText('wazuh')).toBeInTheDocument()
      expect(screen.getByText('evt-7781')).toBeInTheDocument()
      expect(screen.getByText('proc_access_win_lsass')).toBeInTheDocument()
      expect(screen.getByText('1,204')).toBeInTheDocument()
      expect(screen.getByText('(TA0006)')).toBeInTheDocument()
      expect(screen.getByText('Unassigned')).toBeInTheDocument()
      expect(screen.getByText('T1003.002')).toBeInTheDocument()
      expect(screen.getByText('T1558')).toBeInTheDocument()
    })

    it('leaves out fields the backend sent as null', () => {
      renderPanel(
        makeDetection({
          user: null,
          process: null,
          log_source: null,
          event_id: null,
          occurrence_count: null,
          description: null,
          cvss_v3: null,
          confidence: null,
          related_technique_ids: [],
        }),
      )
      expect(screen.queryByText(/Confidence/)).not.toBeInTheDocument()
      expect(screen.queryByText(/CVSS/)).not.toBeInTheDocument()
      expect(screen.queryByText('User')).not.toBeInTheDocument()
      expect(screen.queryByText('Process')).not.toBeInTheDocument()
      expect(screen.queryByText('Occurrences')).not.toBeInTheDocument()
      expect(screen.queryByText('Related techniques')).not.toBeInTheDocument()
    })

    it('calls onClose from the close button and on Escape', () => {
      const onClose = vi.fn()
      renderPanel(makeDetection(), { onClose })
      fireEvent.click(screen.getByRole('button', { name: 'Close' }))
      expect(onClose).toHaveBeenCalledTimes(1)

      fireEvent.keyDown(screen.getByRole('dialog'), { key: 'Escape' })
      expect(onClose).toHaveBeenCalledTimes(2)
    })
  })

  describe('status actions', () => {
    function actionNames() {
      return ['Investigate', 'Resolve', 'False positive', 'Reopen'].filter((name) =>
        screen.queryByRole('button', { name }),
      )
    }

    it('offers the changes that make sense for the current status', () => {
      const { unmount } = renderPanel(makeDetection({ status: 'active' }))
      expect(actionNames()).toEqual(['Investigate', 'Resolve', 'False positive'])
      unmount()

      const second = renderPanel(makeDetection({ status: 'investigating' }))
      expect(actionNames()).toEqual(['Resolve', 'False positive', 'Reopen'])
      second.unmount()

      renderPanel(makeDetection({ status: 'resolved' }))
      expect(actionNames()).toEqual(['Reopen'])
    })

    it('updates the status and hands the server copy back', async () => {
      const updated = makeDetection({ status: 'investigating' })
      updateMock.mockResolvedValue(updated)
      const onUpdated = vi.fn()
      const { invalidate, onClose } = renderPanel(makeDetection(), { onUpdated })

      fireEvent.click(screen.getByRole('button', { name: 'Investigate' }))

      await waitFor(() => expect(updateMock).toHaveBeenCalledWith('det-001', { status: 'investigating' }))
      await waitFor(() => expect(onUpdated).toHaveBeenCalledWith(updated))
      expect(invalidate).toHaveBeenCalledWith({ queryKey: ['detections'] })
      expect(onClose).not.toHaveBeenCalled()
      expect(notifications()).toEqual([
        expect.objectContaining({ type: 'success', title: 'Detection set to investigating' }),
      ])
    })

    it('sends false_positive and resolved with the backend spelling', async () => {
      updateMock.mockResolvedValue(makeDetection({ status: 'false_positive' }))
      renderPanel(makeDetection())
      fireEvent.click(screen.getByRole('button', { name: 'False positive' }))
      await waitFor(() => expect(updateMock).toHaveBeenCalledWith('det-001', { status: 'false_positive' }))
    })

    it('disables the actions while a change is being saved', async () => {
      updateMock.mockReturnValue(new Promise(() => {}))
      renderPanel(makeDetection())
      fireEvent.click(screen.getByRole('button', { name: 'Resolve' }))
      await waitFor(() => expect(screen.getByRole('button', { name: 'Investigate' })).toBeDisabled())
      expect(screen.getByRole('button', { name: 'Resolve' })).toBeDisabled()
    })

    it('reports a failed update', async () => {
      updateMock.mockRejectedValue(new Error('Detection det-001 not found'))
      const onUpdated = vi.fn()
      renderPanel(makeDetection(), { onUpdated })
      fireEvent.click(screen.getByRole('button', { name: 'Resolve' }))

      await waitFor(() =>
        expect(notifications()).toEqual([
          expect.objectContaining({
            type: 'error',
            title: 'Could not update the detection',
            message: 'Detection det-001 not found',
          }),
        ]),
      )
      expect(onUpdated).not.toHaveBeenCalled()
    })
  })

  describe('assignment', () => {
    it('assigns the detection to the entered person', async () => {
      updateMock.mockResolvedValue(makeDetection({ assigned_to: 'kim@mxtac.local' }))
      renderPanel(makeDetection())
      const assign = screen.getByRole('button', { name: 'Assign' })
      expect(assign).toBeDisabled()

      fireEvent.change(screen.getByLabelText('Assign to'), { target: { value: ' kim@mxtac.local ' } })
      expect(assign).toBeEnabled()
      fireEvent.click(assign)

      await waitFor(() => expect(updateMock).toHaveBeenCalledWith('det-001', { assigned_to: 'kim@mxtac.local' }))
      await waitFor(() =>
        expect(notifications()).toEqual([
          expect.objectContaining({ type: 'success', title: 'Detection assigned to kim@mxtac.local' }),
        ]),
      )
    })

    it('starts from the current assignee and stays disabled until it changes', () => {
      renderPanel(makeDetection({ assigned_to: 'lee@mxtac.local' }))
      expect(screen.getByLabelText('Assign to')).toHaveValue('lee@mxtac.local')
      expect(screen.getByRole('button', { name: 'Assign' })).toBeDisabled()
    })
  })

  describe('read-only roles', () => {
    it('hides the status actions and the assign form for a viewer', () => {
      useAuthStore.setState({ user: { email: 'viewer@mxtac.local', role: 'viewer' } })
      renderPanel(makeDetection())
      expect(screen.getByRole('dialog', { name: 'Suspicious LSASS access' })).toBeInTheDocument()
      expect(screen.queryByRole('button', { name: 'Investigate' })).not.toBeInTheDocument()
      expect(screen.queryByRole('button', { name: 'Assign' })).not.toBeInTheDocument()
      expect(screen.queryByLabelText('Assign to')).not.toBeInTheDocument()
    })
  })
})
