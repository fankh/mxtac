import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { ScoreCircle, SeverityPill } from '../../components/shared/SeverityBadge'
import type { SeverityLevel } from '../../types/api'

const LEVELS: [SeverityLevel, string, string][] = [
  ['critical', 'Critical', 'sev-critical'],
  ['high', 'High', 'sev-high'],
  ['medium', 'Medium', 'sev-medium'],
  ['low', 'Low', 'sev-low'],
]

describe('SeverityPill', () => {
  it.each(LEVELS)('%s shows the label "%s" with class %s', (severity, label, cls) => {
    render(<SeverityPill severity={severity} />)
    expect(screen.getByText(label)).toHaveClass(cls)
  })

  it('falls back to "Info" for an unknown severity', () => {
    render(<SeverityPill severity={'unknown' as SeverityLevel} />)
    expect(screen.getByText('Info')).toHaveClass('sev-info')
  })

  it('keeps a caller-supplied class next to the severity class', () => {
    render(<SeverityPill severity="high" className="extra" />)
    expect(screen.getByText('High')).toHaveClass('sev-high', 'extra')
  })
})

describe('ScoreCircle', () => {
  it.each(LEVELS)('%s is labelled with the score and "%s" and has class %s', (severity, label, cls) => {
    render(<ScoreCircle score={7.5} severity={severity} />)
    expect(screen.getByLabelText(`Score 7.5, ${label}`)).toHaveClass(cls)
  })

  it('shows the score with one decimal place', () => {
    render(<ScoreCircle score={9} severity="critical" />)
    expect(screen.getByText('9.0')).toBeInTheDocument()
  })

  it('rounds to one decimal place', () => {
    render(<ScoreCircle score={8.26} severity="high" />)
    expect(screen.getByText('8.3')).toBeInTheDocument()
  })

  it('falls back to "Info" for an unknown severity', () => {
    render(<ScoreCircle score={1} severity={'unknown' as SeverityLevel} />)
    expect(screen.getByLabelText('Score 1, Info')).toHaveClass('sev-info')
  })
})
