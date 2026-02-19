import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { SeverityPill, ScoreCircle } from '../../components/shared/SeverityBadge'

describe('SeverityPill', () => {
  it('renders critical label', () => {
    render(<SeverityPill severity="critical" />)
    expect(screen.getByText('Critical')).toBeInTheDocument()
  })

  it('renders high label', () => {
    render(<SeverityPill severity="high" />)
    expect(screen.getByText('High')).toBeInTheDocument()
  })

  it('renders medium label', () => {
    render(<SeverityPill severity="medium" />)
    expect(screen.getByText('Medium')).toBeInTheDocument()
  })

  it('renders low label', () => {
    render(<SeverityPill severity="low" />)
    expect(screen.getByText('Low')).toBeInTheDocument()
  })
})

describe('ScoreCircle', () => {
  it('renders the score value', () => {
    render(<ScoreCircle score={9.2} severity="critical" />)
    expect(screen.getByText('9.2')).toBeInTheDocument()
  })
})
