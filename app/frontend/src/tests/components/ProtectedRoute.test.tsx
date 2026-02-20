import { render, screen } from '@testing-library/react'
import { describe, it, expect, beforeEach, vi } from 'vitest'
import { MemoryRouter, Routes, Route } from 'react-router-dom'

// vi.mock is hoisted — runs before imports
vi.mock('../../stores/authStore', () => ({
  useAuthStore: vi.fn(),
}))

import { ProtectedRoute } from '../../components/shared/ProtectedRoute'
import { useAuthStore } from '../../stores/authStore'

const mockUseAuthStore = useAuthStore as unknown as ReturnType<typeof vi.fn>

function renderWithRouter(
  isAuthenticated: boolean,
  initialPath = '/',
) {
  return render(
    <MemoryRouter initialEntries={[initialPath]}>
      <Routes>
        <Route path="/login" element={<div>Login page</div>} />
        <Route
          path="/*"
          element={
            <ProtectedRoute>
              <div>Protected content</div>
            </ProtectedRoute>
          }
        />
      </Routes>
    </MemoryRouter>,
  )
}

function mockAuth(isAuthenticated: boolean) {
  // ProtectedRoute calls useAuthStore(s => s.isAuthenticated) — apply the selector
  mockUseAuthStore.mockImplementation(
    (selector: (s: { isAuthenticated: boolean }) => unknown) =>
      selector({ isAuthenticated }),
  )
}

describe('ProtectedRoute', () => {
  beforeEach(() => {
    mockAuth(false)
  })

  // ---------------------------------------------------------------------------
  // Authenticated user
  // ---------------------------------------------------------------------------
  describe('authenticated user', () => {
    beforeEach(() => {
      mockAuth(true)
    })

    it('renders children when user is authenticated', () => {
      renderWithRouter(true)
      expect(screen.getByText('Protected content')).toBeInTheDocument()
    })

    it('does not redirect when user is authenticated', () => {
      renderWithRouter(true)
      expect(screen.queryByText('Login page')).not.toBeInTheDocument()
    })
  })

  // ---------------------------------------------------------------------------
  // Unauthenticated user
  // ---------------------------------------------------------------------------
  describe('unauthenticated user', () => {
    beforeEach(() => {
      mockUseAuthStore.mockReturnValue({ isAuthenticated: false })
    })

    it('redirects to /login when user is not authenticated', () => {
      renderWithRouter(false)
      expect(screen.getByText('Login page')).toBeInTheDocument()
    })

    it('does not render protected children when user is not authenticated', () => {
      renderWithRouter(false)
      expect(screen.queryByText('Protected content')).not.toBeInTheDocument()
    })

    it('redirects to /login from any protected path', () => {
      renderWithRouter(false, '/detections')
      expect(screen.getByText('Login page')).toBeInTheDocument()
    })

    it('redirects to /login from the root path when unauthenticated', () => {
      renderWithRouter(false, '/')
      expect(screen.getByText('Login page')).toBeInTheDocument()
    })
  })

  // ---------------------------------------------------------------------------
  // Login page remains accessible
  // ---------------------------------------------------------------------------
  describe('login route accessibility', () => {
    it('login page is accessible without authentication', () => {
      render(
        <MemoryRouter initialEntries={['/login']}>
          <Routes>
            <Route path="/login" element={<div>Login page</div>} />
            <Route
              path="/*"
              element={
                <ProtectedRoute>
                  <div>Protected content</div>
                </ProtectedRoute>
              }
            />
          </Routes>
        </MemoryRouter>,
      )
      expect(screen.getByText('Login page')).toBeInTheDocument()
    })
  })
})
