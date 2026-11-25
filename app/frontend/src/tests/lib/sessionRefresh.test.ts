import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { delay, http, HttpResponse } from 'msw'
import { server } from '../mocks/server'
import {
  authApi, clearSession, detectionsApi, endSession, getAccessToken, pageNavigation, refreshAccessToken,
  RETURN_TO_KEY, SESSION_ENDED_KEY, setAccessToken,
} from '../../lib/api'

// Silent refresh of the API client (lib/api.ts): a 401 is answered with one POST /auth/refresh,
// the request is repeated with the new access token, and only a refused refresh signs the user out.

const BASE = '/api/v1'
const ME = { email: 'analyst@mxtac.local', role: 'analyst', full_name: null, mfa_enabled: false }
const UNAUTHORIZED = { detail: 'Invalid or expired token' }

const session = (access_token: string) => ({
  access_token, token_type: 'bearer', expires_in: 3600, email: ME.email, role: ME.role,
})

/** Protected routes that accept exactly one access token; every Authorization header seen is recorded. */
function acceptOnly(validToken: () => string, seen: string[] = []) {
  const check = ({ request }: { request: Request }) => {
    const header = request.headers.get('authorization') ?? ''
    seen.push(header)
    return header === `Bearer ${validToken()}`
  }
  server.use(
    http.get(`${BASE}/auth/me`, (info) =>
      check(info) ? HttpResponse.json(ME) : HttpResponse.json(UNAUTHORIZED, { status: 401 })),
    http.get(`${BASE}/detections`, (info) =>
      check(info)
        ? HttpResponse.json({ items: [], pagination: { page: 1, page_size: 25, total: 0, total_pages: 0 } })
        : HttpResponse.json(UNAUTHORIZED, { status: 401 })),
  )
  return seen
}

/** POST /auth/refresh that hands out `tokens` in order; returns the call counter. */
function refreshIssues(...tokens: string[]) {
  const calls = { count: 0 }
  server.use(
    http.post(`${BASE}/auth/refresh`, async () => {
      calls.count += 1
      await delay(15)
      const token = tokens[calls.count - 1]
      return token
        ? HttpResponse.json(session(token))
        : HttpResponse.json({ detail: 'Session has ended. Sign in again.' }, { status: 401 })
    }),
  )
  return calls
}

describe('silent session refresh', () => {
  let navigate: ReturnType<typeof vi.spyOn>

  beforeEach(() => {
    localStorage.clear()
    sessionStorage.clear()
    window.history.replaceState({}, '', '/detections')
    navigate = vi.spyOn(pageNavigation, 'replace').mockImplementation(() => {})
    setAccessToken('expired')
  })

  afterEach(() => {
    navigate.mockRestore()
    localStorage.clear()
    sessionStorage.clear()
    window.history.replaceState({}, '', '/')
  })

  describe('retry', () => {
    it('refreshes after a 401 and repeats the request with the new access token', async () => {
      const seen = acceptOnly(() => 'fresh')
      const refresh = refreshIssues('fresh')

      await expect(authApi.me()).resolves.toEqual(ME)

      expect(refresh.count).toBe(1)
      expect(seen).toEqual(['Bearer expired', 'Bearer fresh'])
      expect(getAccessToken()).toBe('fresh')
    })

    it('does not sign the user out and leaves no notice', async () => {
      acceptOnly(() => 'fresh')
      refreshIssues('fresh')

      await authApi.me()

      expect(navigate).not.toHaveBeenCalled()
      expect(sessionStorage.getItem(SESSION_ENDED_KEY)).toBeNull()
    })

    it('sends later requests with the new token without another refresh', async () => {
      const seen = acceptOnly(() => 'fresh')
      const refresh = refreshIssues('fresh')

      await authApi.me()
      await authApi.me()

      expect(refresh.count).toBe(1)
      expect(seen[seen.length - 1]).toBe('Bearer fresh')
    })

    it('refreshes again when the next access token expires as well', async () => {
      let valid = 'second'
      acceptOnly(() => valid)
      const refresh = refreshIssues('second', 'third')

      await authApi.me()
      valid = 'third'
      await expect(authApi.me()).resolves.toEqual(ME)

      expect(refresh.count).toBe(2)
      expect(getAccessToken()).toBe('third')
    })
  })

  describe('single flight', () => {
    it('shares one refresh between concurrent 401s and repeats every request', async () => {
      const seen = acceptOnly(() => 'fresh')
      const refresh = refreshIssues('fresh')

      const results = await Promise.all([
        authApi.me(), authApi.me(), detectionsApi.list(), authApi.me(), detectionsApi.list(),
      ])

      expect(refresh.count).toBe(1)
      expect(results[0]).toEqual(ME)
      expect(results[2]).toMatchObject({ items: [] })
      expect(seen.filter((h) => h === 'Bearer expired')).toHaveLength(5)
      expect(seen.filter((h) => h === 'Bearer fresh')).toHaveLength(5)
    })

    it('returns the same promise while a refresh is running, and a new one afterwards', async () => {
      const refresh = refreshIssues('one', 'two')

      const first = refreshAccessToken('expired')
      const second = refreshAccessToken('expired')
      expect(second).toBe(first)
      await expect(first).resolves.toBe('one')

      await expect(refreshAccessToken('one')).resolves.toBe('two')
      expect(refresh.count).toBe(2)
    })

    it('uses the token another tab stored instead of refreshing again', async () => {
      const seen: string[] = []
      const refresh = refreshIssues('unused')
      server.use(
        http.get(`${BASE}/auth/me`, ({ request }) => {
          const header = request.headers.get('authorization') ?? ''
          seen.push(header)
          if (header === 'Bearer from-other-tab') return HttpResponse.json(ME)
          // While this request was on its way, another tab finished its own refresh.
          localStorage.setItem('access_token', 'from-other-tab')
          return HttpResponse.json(UNAUTHORIZED, { status: 401 })
        }),
      )

      await expect(authApi.me()).resolves.toEqual(ME)

      expect(refresh.count).toBe(0)
      expect(seen).toEqual(['Bearer expired', 'Bearer from-other-tab'])
    })
  })

  describe('refresh failure', () => {
    it('signs out with a notice and remembers the open page when the refresh is refused', async () => {
      window.history.replaceState({}, '', '/hunt?event=3f6c1a52-7a0e-4c53-9d8b-0c1d2e3f4a5b')
      localStorage.setItem('mxtac-auth', '{"state":{"isAuthenticated":true}}')
      acceptOnly(() => 'never')
      const refresh = refreshIssues()

      const error = await authApi.me().catch((e: unknown) => e)

      expect((error as { response: { status: number } }).response.status).toBe(401)
      expect(refresh.count).toBe(1)
      expect(getAccessToken()).toBeNull()
      expect(localStorage.getItem('mxtac-auth')).toBeNull()
      expect(sessionStorage.getItem(SESSION_ENDED_KEY)).toBe('1')
      expect(sessionStorage.getItem(RETURN_TO_KEY)).toBe('/hunt?event=3f6c1a52-7a0e-4c53-9d8b-0c1d2e3f4a5b')
      expect(navigate).toHaveBeenCalledWith('/login')
    })

    it('rejects every waiting request and navigates to the login page', async () => {
      acceptOnly(() => 'never')
      const refresh = refreshIssues()

      const results = await Promise.allSettled([authApi.me(), authApi.me(), detectionsApi.list()])

      expect(results.map((r) => r.status)).toEqual(['rejected', 'rejected', 'rejected'])
      expect(refresh.count).toBe(1)
      expect(navigate).toHaveBeenCalledWith('/login')
    })

    it('keeps the session when the refresh fails for another reason than a refusal', async () => {
      acceptOnly(() => 'never')
      server.use(http.post(`${BASE}/auth/refresh`, () => HttpResponse.json({ detail: 'down' }, { status: 503 })))

      await expect(authApi.me()).rejects.toMatchObject({ response: { status: 401 } })

      expect(getAccessToken()).toBe('expired')
      expect(navigate).not.toHaveBeenCalled()
      expect(sessionStorage.getItem(SESSION_ENDED_KEY)).toBeNull()
    })

    it('gives up when fresh tokens keep being refused', async () => {
      acceptOnly(() => 'never')
      const refresh = refreshIssues('a', 'b', 'c')

      await expect(authApi.me()).rejects.toMatchObject({ response: { status: 401 } })

      expect(refresh.count).toBe(2)
      expect(navigate).toHaveBeenCalledWith('/login')
    })

    it('does not refresh for a 401 of a sign-in step', async () => {
      const refresh = refreshIssues('fresh')

      await expect(authApi.login('analyst@mxtac.local', 'wrong')).rejects.toMatchObject({ response: { status: 401 } })
      await expect(authApi.changePasswordWithToken('other-token', 'Brand-New-Passw0rd'))
        .rejects.toMatchObject({ response: { status: 401 } })

      expect(refresh.count).toBe(0)
      expect(navigate).not.toHaveBeenCalled()
    })

    it('does not refresh for errors other than 401', async () => {
      const refresh = refreshIssues('fresh')
      server.use(http.get(`${BASE}/auth/me`, () => HttpResponse.json({ detail: 'Forbidden' }, { status: 403 })))

      await expect(authApi.me()).rejects.toMatchObject({ response: { status: 403 } })

      expect(refresh.count).toBe(0)
    })
  })

  describe('endSession and clearSession', () => {
    it('endSession on the login page clears the session without notice or navigation', () => {
      window.history.replaceState({}, '', '/login')

      endSession()

      expect(getAccessToken()).toBeNull()
      expect(sessionStorage.getItem(SESSION_ENDED_KEY)).toBeNull()
      expect(navigate).not.toHaveBeenCalled()
    })

    it('clearSession (sign-out) leaves no notice behind', () => {
      sessionStorage.setItem(SESSION_ENDED_KEY, '1')
      sessionStorage.setItem(RETURN_TO_KEY, '/rules')

      clearSession()

      expect(getAccessToken()).toBeNull()
      expect(sessionStorage.getItem(SESSION_ENDED_KEY)).toBeNull()
      expect(sessionStorage.getItem(RETURN_TO_KEY)).toBeNull()
    })
  })

  describe('sign-out and password change', () => {
    it('repeats the sign-out with a refreshed token so the server can end the session', async () => {
      const seen: string[] = []
      refreshIssues('fresh')
      server.use(
        http.post(`${BASE}/auth/logout`, ({ request }) => {
          const header = request.headers.get('authorization') ?? ''
          seen.push(header)
          return header === 'Bearer fresh'
            ? HttpResponse.json({ message: 'Logged out' })
            : HttpResponse.json(UNAUTHORIZED, { status: 401 })
        }),
      )

      await authApi.logout()

      expect(seen).toEqual(['Bearer expired', 'Bearer fresh'])
    })

    it('stores the access token of the session a password change answers with', async () => {
      setAccessToken('current')
      server.use(
        http.post(`${BASE}/auth/password`, () => HttpResponse.json(session('after-password-change'))),
      )

      await expect(authApi.changePassword('Analyst-Passw0rd', 'Brand-New-Passw0rd')).resolves.toBeUndefined()

      expect(getAccessToken()).toBe('after-password-change')
    })
  })
})
