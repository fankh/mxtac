import { render, screen } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { TopBar } from '../../components/layout/TopBar'
import { useAlertStream } from '../../hooks/useAlertStream'
import type { ConnectionState } from '../../hooks/useAlertStream'

// TopBar renders without a real WebSocket connection
vi.mock('../../hooks/useAlertStream')

const mockUseAlertStream = vi.mocked(useAlertStream)

describe('TopBar', () => {
  beforeEach(() => {
    mockUseAlertStream.mockReturnValue('connected')
  })

  it('shows the page title as the level-1 heading inside the banner', () => {
    render(<TopBar crumb="Detections" />)
    expect(screen.getByRole('banner')).toContainElement(
      screen.getByRole('heading', { level: 1, name: 'Detections' }),
    )
  })

  it('shows the description when one is given', () => {
    render(<TopBar crumb="Overview" description="Detections, coverage and source health" />)
    expect(screen.getByText('Detections, coverage and source health')).toBeInTheDocument()
  })

  it('renders no description paragraph when none is given', () => {
    const { container } = render(<TopBar crumb="Overview" />)
    expect(container.querySelector('p')).toBeNull()
  })

  it('renders the actions', () => {
    render(<TopBar crumb="Rules" actions={<button>New rule</button>} />)
    expect(screen.getByRole('button', { name: 'New rule' })).toBeInTheDocument()
  })

  it('shows "Updated <time>" only when updatedAt is given', () => {
    const { rerender } = render(<TopBar crumb="Overview" />)
    expect(screen.queryByText(/^Updated/)).not.toBeInTheDocument()
    rerender(<TopBar crumb="Overview" updatedAt="2 min ago" />)
    expect(screen.getByText('Updated 2 min ago')).toBeInTheDocument()
  })

  it.each<[ConnectionState, string, string]>([
    ['connected', 'Live', 'Alert stream: live'],
    ['reconnecting', 'Reconnecting', 'Alert stream: reconnecting'],
    ['disconnected', 'Offline', 'Alert stream: offline'],
  ])('alert stream state %s shows "%s"', (state, label, title) => {
    mockUseAlertStream.mockReturnValue(state)
    render(<TopBar crumb="Overview" />)
    expect(screen.getByTitle(title)).toHaveTextContent(label)
  })

  it('shows "Offline" for an unknown stream state', () => {
    mockUseAlertStream.mockReturnValue('bogus' as ConnectionState)
    render(<TopBar crumb="Overview" />)
    expect(screen.getByText('Offline')).toBeInTheDocument()
  })
})
