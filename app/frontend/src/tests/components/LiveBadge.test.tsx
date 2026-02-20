import { render, screen, act } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { LiveBadge } from '../../components/shared/LiveBadge'

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

describe('LiveBadge', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  // =========================================================================
  // Rendering
  // =========================================================================
  describe('rendering', () => {
    it('renders the "LIVE" label', () => {
      render(<LiveBadge />)
      expect(screen.getByText('LIVE')).toBeInTheDocument()
    })

    it('renders a <span> element', () => {
      render(<LiveBadge />)
      expect(screen.getByText('LIVE').tagName).toBe('SPAN')
    })

    it('is visible on mount (opacity-100 class)', () => {
      render(<LiveBadge />)
      expect(screen.getByText('LIVE')).toHaveClass('opacity-100')
    })

    it('does not have opacity-0 class on mount', () => {
      render(<LiveBadge />)
      expect(screen.getByText('LIVE')).not.toHaveClass('opacity-0')
    })

    it('has the bg-status-ok class (green background)', () => {
      render(<LiveBadge />)
      expect(screen.getByText('LIVE')).toHaveClass('bg-status-ok')
    })

    it('has the text-white class', () => {
      render(<LiveBadge />)
      expect(screen.getByText('LIVE')).toHaveClass('text-white')
    })

    it('has the transition-opacity class for smooth fade', () => {
      render(<LiveBadge />)
      expect(screen.getByText('LIVE')).toHaveClass('transition-opacity')
    })

    it('has font-bold class', () => {
      render(<LiveBadge />)
      expect(screen.getByText('LIVE')).toHaveClass('font-bold')
    })
  })

  // =========================================================================
  // Fade-out at 30 s
  // =========================================================================
  describe('fade-out at 30 s', () => {
    it('switches to opacity-0 after 30 s', () => {
      render(<LiveBadge />)

      act(() => {
        vi.advanceTimersByTime(30_000)
      })

      expect(screen.getByText('LIVE')).toHaveClass('opacity-0')
    })

    it('removes opacity-100 after 30 s', () => {
      render(<LiveBadge />)

      act(() => {
        vi.advanceTimersByTime(30_000)
      })

      expect(screen.getByText('LIVE')).not.toHaveClass('opacity-100')
    })

    it('is still in the DOM immediately after 30 s (fade transition in progress)', () => {
      render(<LiveBadge />)

      act(() => {
        vi.advanceTimersByTime(30_000)
      })

      expect(screen.queryByText('LIVE')).toBeInTheDocument()
    })

    it('remains visible at 29 999 ms (just before fade starts)', () => {
      render(<LiveBadge />)

      act(() => {
        vi.advanceTimersByTime(29_999)
      })

      expect(screen.getByText('LIVE')).toHaveClass('opacity-100')
      expect(screen.getByText('LIVE')).not.toHaveClass('opacity-0')
    })
  })

  // =========================================================================
  // Removal from DOM at 30 600 ms
  // =========================================================================
  describe('DOM removal at 30 600 ms', () => {
    it('is removed from the DOM after 30 600 ms', () => {
      render(<LiveBadge />)

      act(() => {
        vi.advanceTimersByTime(30_600)
      })

      expect(screen.queryByText('LIVE')).not.toBeInTheDocument()
    })

    it('is still in the DOM at 30 599 ms (fade still in progress)', () => {
      render(<LiveBadge />)

      act(() => {
        vi.advanceTimersByTime(30_599)
      })

      expect(screen.queryByText('LIVE')).toBeInTheDocument()
    })
  })

  // =========================================================================
  // Cleanup on unmount
  // =========================================================================
  describe('cleanup on unmount', () => {
    it('does not throw when unmounted before fade timer fires', () => {
      const { unmount } = render(<LiveBadge />)

      expect(() => {
        unmount()
        act(() => {
          vi.advanceTimersByTime(31_000)
        })
      }).not.toThrow()
    })
  })
})
