import { render, screen } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import { Page } from '../../components/layout/Page'

vi.mock('../../hooks/useAlertStream', () => ({ useAlertStream: () => 'disconnected' }))

describe('Page', () => {
  it('shows the title as the page heading and renders its children', () => {
    render(<Page title="Sources"><p>Body content</p></Page>)
    expect(screen.getByRole('heading', { level: 1, name: 'Sources' })).toBeInTheDocument()
    expect(screen.getByText('Body content')).toBeInTheDocument()
  })

  it('shows the description and the actions in the header bar', () => {
    render(
      <Page title="Sources" description="Connector health" actions={<button>Add a source</button>}>
        <p>Body content</p>
      </Page>,
    )
    const header = screen.getByRole('banner')
    expect(header).toHaveTextContent('Connector health')
    expect(header).toContainElement(screen.getByRole('button', { name: 'Add a source' }))
  })

  it('keeps the children outside the header bar', () => {
    render(<Page title="Sources"><p>Body content</p></Page>)
    expect(screen.getByRole('banner')).not.toContainElement(screen.getByText('Body content'))
  })

  it('passes className on to the body wrapper', () => {
    render(<Page title="Hunt" className="p-0"><p>Body content</p></Page>)
    expect(screen.getByText('Body content').parentElement).toHaveClass('p-0')
  })
})
