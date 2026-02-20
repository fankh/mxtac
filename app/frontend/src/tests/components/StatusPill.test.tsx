import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { StatusPill } from '../../components/shared/StatusPill'

// ---------------------------------------------------------------------------
// StatusPill
// ---------------------------------------------------------------------------

describe('StatusPill', () => {
  // =========================================================================
  // Label rendering — all detection statuses
  // =========================================================================
  describe('label rendering', () => {
    it('renders "Active" for status="active"', () => {
      render(<StatusPill status="active" />)
      expect(screen.getByText('Active')).toBeInTheDocument()
    })

    it('renders "Investigating" for status="investigating"', () => {
      render(<StatusPill status="investigating" />)
      expect(screen.getByText('Investigating')).toBeInTheDocument()
    })

    it('renders "Resolved" for status="resolved"', () => {
      render(<StatusPill status="resolved" />)
      expect(screen.getByText('Resolved')).toBeInTheDocument()
    })

    it('renders "False Positive" for status="false_positive"', () => {
      render(<StatusPill status="false_positive" />)
      expect(screen.getByText('False Positive')).toBeInTheDocument()
    })

    it('renders only one text node (no extra content) for status="active"', () => {
      const { container } = render(<StatusPill status="active" />)
      expect(container.firstChild?.textContent).toBe('Active')
    })

    it('renders only one text node (no extra content) for status="false_positive"', () => {
      const { container } = render(<StatusPill status="false_positive" />)
      expect(container.firstChild?.textContent).toBe('False Positive')
    })
  })

  // =========================================================================
  // Element structure
  // =========================================================================
  describe('element structure', () => {
    it('renders a <span> element for status="active"', () => {
      render(<StatusPill status="active" />)
      expect(screen.getByText('Active').tagName).toBe('SPAN')
    })

    it('renders a <span> element for status="resolved"', () => {
      render(<StatusPill status="resolved" />)
      expect(screen.getByText('Resolved').tagName).toBe('SPAN')
    })
  })

  // =========================================================================
  // Common CSS classes (applied to every status)
  // =========================================================================
  describe('common CSS classes', () => {
    const COMMON_CLASSES = [
      'inline-block',
      'px-2',
      'py-0.5',
      'rounded-full',
      'font-medium',
    ]

    COMMON_CLASSES.forEach((cls) => {
      it(`applies "${cls}" class regardless of status`, () => {
        render(<StatusPill status="active" />)
        expect(screen.getByText('Active')).toHaveClass(cls)
      })
    })

    it('applies all common classes together', () => {
      render(<StatusPill status="investigating" />)
      const el = screen.getByText('Investigating')
      expect(el).toHaveClass('inline-block', 'px-2', 'py-0.5', 'rounded-full', 'font-medium')
    })
  })

  // =========================================================================
  // Status-specific CSS classes
  // =========================================================================
  describe('status-specific CSS classes', () => {
    const STATUS_CASES = [
      { status: 'active'        as const, label: 'Active',        bgClass: 'bg-crit-bg',     textClass: 'text-crit-text'     },
      { status: 'investigating' as const, label: 'Investigating',  bgClass: 'bg-high-bg',     textClass: 'text-high-text'     },
      { status: 'resolved'      as const, label: 'Resolved',       bgClass: 'bg-resolved-bg', textClass: 'text-resolved-text' },
      { status: 'false_positive'as const, label: 'False Positive', bgClass: 'bg-low-bg',      textClass: 'text-low-text'      },
    ]

    STATUS_CASES.forEach(({ status, label, bgClass, textClass }) => {
      describe(`status="${status}"`, () => {
        it(`applies background class "${bgClass}"`, () => {
          render(<StatusPill status={status} />)
          expect(screen.getByText(label)).toHaveClass(bgClass)
        })

        it(`applies text class "${textClass}"`, () => {
          render(<StatusPill status={status} />)
          expect(screen.getByText(label)).toHaveClass(textClass)
        })
      })
    })
  })

  // =========================================================================
  // All four statuses — smoke tests
  // =========================================================================
  describe('all detection statuses render without error', () => {
    const STATUSES = ['active', 'investigating', 'resolved', 'false_positive'] as const

    STATUSES.forEach((status) => {
      it(`renders for status="${status}"`, () => {
        expect(() => render(<StatusPill status={status} />)).not.toThrow()
      })
    })
  })
})
