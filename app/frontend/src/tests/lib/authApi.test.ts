import { describe, expect, it } from 'vitest'
import { apiErrorMessage, authApi } from '../../lib/api'
import { PASSWORD_POLICY_HINT, passwordErrorMessage, passwordProblem } from '../../lib/passwordPolicy'

// These run against the MSW handlers in src/tests/mocks/handlers.ts, which mirror the backend shapes.

describe('authApi sign-in steps', () => {
  it('returns the session for a normal login', async () => {
    const data = await authApi.login('analyst@mxtac.local', 'Analyst-Passw0rd')
    expect(data).toMatchObject({
      access_token: 'mock-token-abc123', token_type: 'bearer', email: 'analyst@mxtac.local', role: 'analyst',
    })
    expect(data.password_change_required).toBeUndefined()
  })

  it('returns the password-change token for an account with a temporary password', async () => {
    const data = await authApi.login('new@mxtac.local', 'Temp-Passw0rd')
    expect(data).toEqual({ password_change_required: true, password_change_token: 'mock-password-change-token' })
  })

  it('sets the new password with the token and gets the session back', async () => {
    const data = await authApi.changePasswordWithToken('mock-password-change-token', 'Brand-New-Passw0rd')
    expect(data).toMatchObject({ access_token: 'mock-token-abc123', email: 'new@mxtac.local' })
  })

  it('rejects with the server message when the new password is refused', async () => {
    const err = await authApi.changePasswordWithToken('mock-password-change-token', 'Temp-Passw0rd').catch((e: unknown) => e)
    expect(apiErrorMessage(err, 'fallback')).toBe('Cannot reuse one of your last 2 passwords')
  })

  it('rejects an unknown token', async () => {
    const err = await authApi.changePasswordWithToken('other-token', 'Brand-New-Passw0rd').catch((e: unknown) => e)
    expect(apiErrorMessage(err, 'fallback')).toBe('Invalid or expired token')
  })
})

describe('authApi.changePassword', () => {
  it('resolves with nothing and keeps the new access token', async () => {
    await expect(authApi.changePassword('Analyst-Passw0rd', 'Brand-New-Passw0rd')).resolves.toBeUndefined()
    expect(localStorage.getItem('access_token')).toBe('mock-token-after-password-change')
    localStorage.removeItem('access_token')
  })

  it('rejects with the server message for a wrong current password', async () => {
    const err = await authApi.changePassword('Wrong-Passw0rd', 'Brand-New-Passw0rd').catch((e: unknown) => e)
    expect(apiErrorMessage(err, 'fallback')).toBe('Current password is incorrect')
  })
})

describe('passwordErrorMessage', () => {
  it('drops the "Value error" prefix of validator messages', () => {
    const err = { response: { data: { detail: [
      { msg: 'Value error, Password must not contain more than 3 consecutive identical characters' },
      { msg: 'Value error, passwords do not match' },
    ] } } }
    expect(passwordErrorMessage(err, 'fallback')).toBe(
      'Password must not contain more than 3 consecutive identical characters; passwords do not match',
    )
  })

  it('keeps plain server messages', () => {
    expect(passwordErrorMessage({ response: { data: { detail: 'Current password is incorrect' } } }, 'fallback'))
      .toBe('Current password is incorrect')
  })

  it('uses the fallback when there is no detail', () => {
    expect(passwordErrorMessage(new Error('boom'), 'fallback')).toBe('fallback')
  })
})

describe('passwordProblem', () => {
  it.each([
    ['Ab1!', 'at least 8 characters'],
    ['Aa1!' + 'xy'.repeat(63), 'at most 128 characters'],
    ['alllowercase', 'at least 3 of'],
    ['lowercase123', 'at least 3 of'],
    ['Abcd1111efgh', 'more than 3 times in a row'],
  ])('rejects %s', (password, message) => {
    expect(passwordProblem(password)).toContain(message)
  })

  it.each(['Brand-New-Passw0rd', 'lowercase123!', 'UPPER123lower', 'Aaa111bbb'])('accepts %s', (password) => {
    expect(passwordProblem(password)).toBe('')
  })

  it('has a one-line hint', () => {
    expect(PASSWORD_POLICY_HINT).not.toContain('\n')
  })
})
