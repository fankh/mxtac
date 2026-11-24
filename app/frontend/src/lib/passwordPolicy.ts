import { apiErrorMessage } from './api'

/** One-line statement of the backend password policy (core/validators.py), shown under password fields. */
export const PASSWORD_POLICY_HINT = 'At least 8 characters with 3 of: uppercase, lowercase, digits, symbols.'

/** The backend password policy (core/validators.py). Returns a message, or '' when the password passes. */
export function passwordProblem(password: string): string {
  if (password.length < 8) return 'The password needs at least 8 characters'
  if (password.length > 128) return 'The password can have at most 128 characters'
  const kinds = [/[A-Z]/, /[a-z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((re) => re.test(password)).length
  if (kinds < 3) return 'Use at least 3 of: uppercase letters, lowercase letters, digits, symbols'
  if (/(.)\1{3,}/.test(password)) return 'Do not repeat the same character more than 3 times in a row'
  return ''
}

/**
 * Message of a failed password request. The server reports policy violations as a 422 whose
 * messages carry Pydantic's "Value error, " prefix; it is removed so the policy text reads cleanly.
 */
export function passwordErrorMessage(err: unknown, fallback: string): string {
  return apiErrorMessage(err, fallback).replace(/(^|; )Value error, /g, '$1')
}
