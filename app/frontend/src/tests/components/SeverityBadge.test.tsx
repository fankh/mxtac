import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { SeverityPill, ScoreCircle } from '../../components/shared/SeverityBadge'

// ---------------------------------------------------------------------------
// SeverityPill
// ---------------------------------------------------------------------------

describe('SeverityPill', () => {
  // =========================================================================
  // Label rendering — all severity levels
  // =========================================================================
  describe('label rendering', () => {
    it('renders "Critical" for severity="critical"', () => {
      render(<SeverityPill severity="critical" />)
      expect(screen.getByText('Critical')).toBeInTheDocument()
    })

    it('renders "High" for severity="high"', () => {
      render(<SeverityPill severity="high" />)
      expect(screen.getByText('High')).toBeInTheDocument()
    })

    it('renders "Medium" for severity="medium"', () => {
      render(<SeverityPill severity="medium" />)
      expect(screen.getByText('Medium')).toBeInTheDocument()
    })

    it('renders "Low" for severity="low"', () => {
      render(<SeverityPill severity="low" />)
      expect(screen.getByText('Low')).toBeInTheDocument()
    })

    it('renders only one text node (no extra content)', () => {
      const { container } = render(<SeverityPill severity="high" />)
      expect(container.firstChild?.textContent).toBe('High')
    })
  })

  // =========================================================================
  // Element structure
  // =========================================================================
  describe('element structure', () => {
    it('renders a <span> element', () => {
      render(<SeverityPill severity="critical" />)
      expect(screen.getByText('Critical').tagName).toBe('SPAN')
    })
  })

  // =========================================================================
  // Common CSS classes (applied to every severity level)
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
      it(`applies "${cls}" class regardless of severity`, () => {
        render(<SeverityPill severity="medium" />)
        expect(screen.getByText('Medium')).toHaveClass(cls)
      })
    })
  })

  // =========================================================================
  // Severity-specific CSS classes
  // =========================================================================
  describe('severity-specific CSS classes', () => {
    const SEVERITY_CASES = [
      { severity: 'critical' as const, label: 'Critical', bgClass: 'bg-crit-bg', textClass: 'text-crit-text' },
      { severity: 'high'     as const, label: 'High',     bgClass: 'bg-high-bg', textClass: 'text-high-text' },
      { severity: 'medium'   as const, label: 'Medium',   bgClass: 'bg-med-bg',  textClass: 'text-med-text'  },
      { severity: 'low'      as const, label: 'Low',      bgClass: 'bg-low-bg',  textClass: 'text-low-text'  },
    ]

    SEVERITY_CASES.forEach(({ severity, label, bgClass, textClass }) => {
      describe(`severity="${severity}"`, () => {
        it(`applies background class "${bgClass}"`, () => {
          render(<SeverityPill severity={severity} />)
          expect(screen.getByText(label)).toHaveClass(bgClass)
        })

        it(`applies text class "${textClass}"`, () => {
          render(<SeverityPill severity={severity} />)
          expect(screen.getByText(label)).toHaveClass(textClass)
        })
      })
    })
  })
})

// ---------------------------------------------------------------------------
// ScoreCircle
// ---------------------------------------------------------------------------

describe('ScoreCircle', () => {
  // =========================================================================
  // Score value rendering
  // =========================================================================
  describe('score value rendering', () => {
    it('renders the score value as text', () => {
      render(<ScoreCircle score={9.2} severity="critical" />)
      expect(screen.getByText('9.2')).toBeInTheDocument()
    })

    it('formats integer scores with one decimal place (e.g., 7 → "7.0")', () => {
      render(<ScoreCircle score={7} severity="high" />)
      expect(screen.getByText('7.0')).toBeInTheDocument()
    })

    it('formats scores with two decimals to one decimal place (rounding, e.g., 9.25 → "9.3")', () => {
      render(<ScoreCircle score={9.25} severity="critical" />)
      expect(screen.getByText('9.3')).toBeInTheDocument()
    })

    it('renders score of 0 as "0.0"', () => {
      render(<ScoreCircle score={0} severity="low" />)
      expect(screen.getByText('0.0')).toBeInTheDocument()
    })

    it('renders score of 10 as "10.0"', () => {
      render(<ScoreCircle score={10} severity="critical" />)
      expect(screen.getByText('10.0')).toBeInTheDocument()
    })

    it('renders the exact text — no surrounding content', () => {
      const { container } = render(<ScoreCircle score={5.5} severity="medium" />)
      expect(container.firstChild?.textContent).toBe('5.5')
    })
  })

  // =========================================================================
  // Element structure
  // =========================================================================
  describe('element structure', () => {
    it('renders a <span> element', () => {
      render(<ScoreCircle score={8.0} severity="high" />)
      expect(screen.getByText('8.0').tagName).toBe('SPAN')
    })
  })

  // =========================================================================
  // Accessibility — aria-label
  // =========================================================================
  describe('aria-label', () => {
    it('includes the score in the aria-label', () => {
      render(<ScoreCircle score={9.2} severity="critical" />)
      expect(screen.getByLabelText(/Score 9\.2/)).toBeInTheDocument()
    })

    it('includes the severity label "Critical" in the aria-label', () => {
      render(<ScoreCircle score={9.2} severity="critical" />)
      expect(screen.getByLabelText(/Critical/)).toBeInTheDocument()
    })

    it('includes "High" in the aria-label for severity="high"', () => {
      render(<ScoreCircle score={7.5} severity="high" />)
      expect(screen.getByLabelText(/High/)).toBeInTheDocument()
    })

    it('includes "Medium" in the aria-label for severity="medium"', () => {
      render(<ScoreCircle score={5.0} severity="medium" />)
      expect(screen.getByLabelText(/Medium/)).toBeInTheDocument()
    })

    it('includes "Low" in the aria-label for severity="low"', () => {
      render(<ScoreCircle score={2.1} severity="low" />)
      expect(screen.getByLabelText(/Low/)).toBeInTheDocument()
    })

    it('aria-label has the exact format "Score {score}, {Label}"', () => {
      render(<ScoreCircle score={9.2} severity="critical" />)
      expect(screen.getByLabelText('Score 9.2, Critical')).toBeInTheDocument()
    })
  })

  // =========================================================================
  // Common CSS classes
  // =========================================================================
  describe('common CSS classes', () => {
    const COMMON_CLASSES = [
      'inline-flex',
      'items-center',
      'justify-center',
      'rounded-full',
      'font-bold',
    ]

    COMMON_CLASSES.forEach((cls) => {
      it(`applies "${cls}" class regardless of severity`, () => {
        render(<ScoreCircle score={5.0} severity="medium" />)
        expect(screen.getByText('5.0')).toHaveClass(cls)
      })
    })
  })

  // =========================================================================
  // Severity-specific CSS classes
  // =========================================================================
  describe('severity-specific CSS classes', () => {
    const SEVERITY_CASES = [
      { severity: 'critical' as const, score: 9.5, bgClass: 'bg-crit-bg', textClass: 'text-crit-text' },
      { severity: 'high'     as const, score: 7.5, bgClass: 'bg-high-bg', textClass: 'text-high-text' },
      { severity: 'medium'   as const, score: 5.0, bgClass: 'bg-med-bg',  textClass: 'text-med-text'  },
      { severity: 'low'      as const, score: 2.0, bgClass: 'bg-low-bg',  textClass: 'text-low-text'  },
    ]

    SEVERITY_CASES.forEach(({ severity, score, bgClass, textClass }) => {
      const label = score.toFixed(1)

      describe(`severity="${severity}"`, () => {
        it(`applies background class "${bgClass}"`, () => {
          render(<ScoreCircle score={score} severity={severity} />)
          expect(screen.getByText(label)).toHaveClass(bgClass)
        })

        it(`applies text class "${textClass}"`, () => {
          render(<ScoreCircle score={score} severity={severity} />)
          expect(screen.getByText(label)).toHaveClass(textClass)
        })
      })
    })
  })

  // =========================================================================
  // All four severity levels — smoke tests
  // =========================================================================
  describe('all severity levels render without error', () => {
    const LEVELS = ['critical', 'high', 'medium', 'low'] as const

    LEVELS.forEach((severity) => {
      it(`renders for severity="${severity}"`, () => {
        expect(() => render(<ScoreCircle score={5.0} severity={severity} />)).not.toThrow()
      })
    })
  })
})
