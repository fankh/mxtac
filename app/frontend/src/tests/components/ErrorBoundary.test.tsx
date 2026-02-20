import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { ErrorBoundary } from '../../components/shared/ErrorBoundary'

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

function NormalChild() {
  return <div>Child content</div>
}

function ThrowingChild({ message = 'Test error' }: { message?: string }): never {
  throw new Error(message)
}

// Throws a non-Error object — state.error.message will be undefined,
// triggering the '?? An unexpected rendering error occurred.' fallback.
function ThrowsNonError(): never {
  throw { code: 'FATAL' } as unknown as Error
}

// ---------------------------------------------------------------------------
// Suppress React's own console.error output during error boundary tests
// ---------------------------------------------------------------------------

let consoleErrorSpy: ReturnType<typeof vi.spyOn>

beforeEach(() => {
  consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
})

afterEach(() => {
  consoleErrorSpy.mockRestore()
})

// ---------------------------------------------------------------------------
// ErrorBoundary
// ---------------------------------------------------------------------------

describe('ErrorBoundary', () => {
  // -------------------------------------------------------------------------
  // Normal operation
  // -------------------------------------------------------------------------
  describe('Normal operation', () => {
    it('renders children when no error occurs', () => {
      render(
        <ErrorBoundary>
          <NormalChild />
        </ErrorBoundary>,
      )
      expect(screen.getByText('Child content')).toBeInTheDocument()
    })

    it('renders multiple children without error', () => {
      render(
        <ErrorBoundary>
          <div>First</div>
          <div>Second</div>
        </ErrorBoundary>,
      )
      expect(screen.getByText('First')).toBeInTheDocument()
      expect(screen.getByText('Second')).toBeInTheDocument()
    })

    it('renders deeply nested children', () => {
      render(
        <ErrorBoundary>
          <div>
            <span>
              <strong>Nested content</strong>
            </span>
          </div>
        </ErrorBoundary>,
      )
      expect(screen.getByText('Nested content')).toBeInTheDocument()
    })

    it('does not show error UI when children render normally', () => {
      render(
        <ErrorBoundary>
          <NormalChild />
        </ErrorBoundary>,
      )
      expect(screen.queryByText('Something went wrong')).not.toBeInTheDocument()
      expect(screen.queryByText('Try again')).not.toBeInTheDocument()
    })

    it('does not render fallback when children succeed even if fallback prop is set', () => {
      render(
        <ErrorBoundary fallback={<div>Custom fallback</div>}>
          <NormalChild />
        </ErrorBoundary>,
      )
      expect(screen.getByText('Child content')).toBeInTheDocument()
      expect(screen.queryByText('Custom fallback')).not.toBeInTheDocument()
    })
  })

  // -------------------------------------------------------------------------
  // Error handling — default UI
  // -------------------------------------------------------------------------
  describe('Error handling — default UI', () => {
    it('shows "Something went wrong" heading when child throws', () => {
      render(
        <ErrorBoundary>
          <ThrowingChild />
        </ErrorBoundary>,
      )
      expect(screen.getByText('Something went wrong')).toBeInTheDocument()
    })

    it('displays the error message from the thrown Error object', () => {
      render(
        <ErrorBoundary>
          <ThrowingChild message="Custom error message" />
        </ErrorBoundary>,
      )
      expect(screen.getByText('Custom error message')).toBeInTheDocument()
    })

    it('shows fallback description when error has no message property', () => {
      render(
        <ErrorBoundary>
          <ThrowsNonError />
        </ErrorBoundary>,
      )
      expect(screen.getByText('An unexpected rendering error occurred.')).toBeInTheDocument()
    })

    it('renders a "Try again" button', () => {
      render(
        <ErrorBoundary>
          <ThrowingChild />
        </ErrorBoundary>,
      )
      expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument()
    })

    it('"Try again" is a <button> element', () => {
      render(
        <ErrorBoundary>
          <ThrowingChild />
        </ErrorBoundary>,
      )
      expect(screen.getByText('Try again').tagName).toBe('BUTTON')
    })

    it('renders all three default-UI elements together', () => {
      render(
        <ErrorBoundary>
          <ThrowingChild message="Oops" />
        </ErrorBoundary>,
      )
      expect(screen.getByText('Something went wrong')).toBeInTheDocument()
      expect(screen.getByText('Oops')).toBeInTheDocument()
      expect(screen.getByText('Try again')).toBeInTheDocument()
    })

    it('hides children content when error occurs', () => {
      render(
        <ErrorBoundary>
          <ThrowingChild />
        </ErrorBoundary>,
      )
      expect(screen.queryByText('Child content')).not.toBeInTheDocument()
    })
  })

  // -------------------------------------------------------------------------
  // Error handling — custom fallback
  // -------------------------------------------------------------------------
  describe('Error handling — custom fallback', () => {
    it('renders custom fallback node when child throws', () => {
      render(
        <ErrorBoundary fallback={<div>Custom fallback UI</div>}>
          <ThrowingChild />
        </ErrorBoundary>,
      )
      expect(screen.getByText('Custom fallback UI')).toBeInTheDocument()
    })

    it('does not render default error heading when custom fallback is used', () => {
      render(
        <ErrorBoundary fallback={<div>Custom fallback UI</div>}>
          <ThrowingChild />
        </ErrorBoundary>,
      )
      expect(screen.queryByText('Something went wrong')).not.toBeInTheDocument()
    })

    it('does not render "Try again" button when custom fallback is used', () => {
      render(
        <ErrorBoundary fallback={<div>Custom fallback UI</div>}>
          <ThrowingChild />
        </ErrorBoundary>,
      )
      expect(screen.queryByRole('button', { name: 'Try again' })).not.toBeInTheDocument()
    })

    it('renders rich fallback content (multiple elements)', () => {
      render(
        <ErrorBoundary
          fallback={
            <div>
              <h2>Error occurred</h2>
              <p>Please contact support.</p>
            </div>
          }
        >
          <ThrowingChild />
        </ErrorBoundary>,
      )
      expect(screen.getByText('Error occurred')).toBeInTheDocument()
      expect(screen.getByText('Please contact support.')).toBeInTheDocument()
    })
  })

  // -------------------------------------------------------------------------
  // "Try again" — reset behavior
  // -------------------------------------------------------------------------
  describe('"Try again" reset behavior', () => {
    it('resets error state and re-renders children when child recovers', () => {
      let shouldThrow = true
      function ConditionalThrow() {
        if (shouldThrow) throw new Error('Boom')
        return <div>Recovered</div>
      }

      render(
        <ErrorBoundary>
          <ConditionalThrow />
        </ErrorBoundary>,
      )

      expect(screen.getByText('Something went wrong')).toBeInTheDocument()

      shouldThrow = false
      fireEvent.click(screen.getByText('Try again'))

      expect(screen.getByText('Recovered')).toBeInTheDocument()
    })

    it('hides error UI after successful reset', () => {
      let shouldThrow = true
      function ConditionalThrow() {
        if (shouldThrow) throw new Error('Boom')
        return <div>OK</div>
      }

      render(
        <ErrorBoundary>
          <ConditionalThrow />
        </ErrorBoundary>,
      )

      shouldThrow = false
      fireEvent.click(screen.getByText('Try again'))

      expect(screen.queryByText('Something went wrong')).not.toBeInTheDocument()
      expect(screen.queryByText('Try again')).not.toBeInTheDocument()
    })

    it('re-shows error UI if child still throws after reset', () => {
      // ThrowingChild always throws — clicking "Try again" resets the boundary,
      // but the child immediately throws again, so the error UI reappears.
      render(
        <ErrorBoundary>
          <ThrowingChild message="Persistent error" />
        </ErrorBoundary>,
      )

      expect(screen.getByText('Something went wrong')).toBeInTheDocument()

      fireEvent.click(screen.getByText('Try again'))

      // Child threw again — error boundary caught it a second time
      expect(screen.getByText('Something went wrong')).toBeInTheDocument()
      expect(screen.getByText('Persistent error')).toBeInTheDocument()
    })
  })

  // -------------------------------------------------------------------------
  // console.error logging (componentDidCatch)
  // -------------------------------------------------------------------------
  describe('console.error logging', () => {
    it('calls console.error when an error is caught', () => {
      render(
        <ErrorBoundary>
          <ThrowingChild message="Logged error" />
        </ErrorBoundary>,
      )
      expect(consoleErrorSpy).toHaveBeenCalled()
    })

    it('logs with the "[ErrorBoundary]" prefix', () => {
      render(
        <ErrorBoundary>
          <ThrowingChild message="Logged error" />
        </ErrorBoundary>,
      )
      const boundaryCall = consoleErrorSpy.mock.calls.find(
        (args) => typeof args[0] === 'string' && args[0].includes('[ErrorBoundary]'),
      )
      expect(boundaryCall).toBeDefined()
    })

    it('logs the thrown Error object', () => {
      render(
        <ErrorBoundary>
          <ThrowingChild message="Traceable error" />
        </ErrorBoundary>,
      )
      const boundaryCall = consoleErrorSpy.mock.calls.find(
        (args) => typeof args[0] === 'string' && args[0].includes('[ErrorBoundary]'),
      )
      expect(boundaryCall).toBeDefined()
      const loggedError = boundaryCall![1] as Error
      expect(loggedError).toBeInstanceOf(Error)
      expect(loggedError.message).toBe('Traceable error')
    })
  })

  // -------------------------------------------------------------------------
  // Layout structure
  // -------------------------------------------------------------------------
  describe('Layout structure', () => {
    it('renders a flex column container when error occurs', () => {
      const { container } = render(
        <ErrorBoundary>
          <ThrowingChild />
        </ErrorBoundary>,
      )
      expect(container.querySelector('.flex.flex-col')).toBeInTheDocument()
    })

    it('renders only one "Try again" button', () => {
      const { container } = render(
        <ErrorBoundary>
          <ThrowingChild />
        </ErrorBoundary>,
      )
      expect(container.querySelectorAll('button')).toHaveLength(1)
    })
  })
})
