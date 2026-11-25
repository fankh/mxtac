import { describe, expect, it } from 'vitest'
import { apiErrorMessage } from '../../lib/api'

const rateLimited = (data: Record<string, unknown>) => ({ response: { status: 429, data } })

describe('apiErrorMessage for a rate-limited request', () => {
  it('says when to try again instead of "Too Many Requests"', () => {
    const err = rateLimited({ detail: 'Too Many Requests', group: 'auth', limit: 10, retry_after: 42 })
    expect(apiErrorMessage(err, 'Login failed')).toBe('Too many requests. Try again in 42 seconds.')
  })

  it('uses the singular and never says 0 seconds', () => {
    expect(apiErrorMessage(rateLimited({ detail: 'Too Many Requests', retry_after: 1 }))).toBe('Too many requests. Try again in 1 second.')
    expect(apiErrorMessage(rateLimited({ detail: 'Too Many Requests', retry_after: 0 }))).toBe('Too many requests. Try again in 1 second.')
  })

  it('keeps the detail of a 429 that carries its own explanation', () => {
    const err = rateLimited({ detail: 'Rate limit exceeded: 100 requests per minute per source' })
    expect(apiErrorMessage(err)).toBe('Rate limit exceeded: 100 requests per minute per source')
  })
})
