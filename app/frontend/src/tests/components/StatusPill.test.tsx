import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { StatusPill } from '../../components/shared/StatusPill'

describe('StatusPill', () => {
  it('renders active', () => {
    render(<StatusPill status="active" />)
    expect(screen.getByText('Active')).toBeInTheDocument()
  })

  it('renders investigating', () => {
    render(<StatusPill status="investigating" />)
    expect(screen.getByText('Investigating')).toBeInTheDocument()
  })

  it('renders resolved', () => {
    render(<StatusPill status="resolved" />)
    expect(screen.getByText('Resolved')).toBeInTheDocument()
  })

  it('renders false positive as FP', () => {
    render(<StatusPill status="false_positive" />)
    expect(screen.getByText('FP')).toBeInTheDocument()
  })
})
