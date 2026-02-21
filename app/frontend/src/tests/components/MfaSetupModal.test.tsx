// vi.mock is hoisted — declare all module mocks before imports.

vi.mock('../../lib/api', () => ({
  authApi: {
    me:              vi.fn(),
    mfaSetup:        vi.fn(),
    mfaVerifySetup:  vi.fn(),
  },
}))

vi.mock('qrcode', () => ({
  default: {
    toDataURL: vi.fn(),
  },
}))

import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { describe, it, expect, beforeEach, vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MfaSetupModal } from '../../components/features/auth/MfaSetupModal'
import { authApi } from '../../lib/api'
import QRCode from 'qrcode'

// ---------------------------------------------------------------------------
// Typed mock references
// ---------------------------------------------------------------------------

const mockMe              = authApi.me              as ReturnType<typeof vi.fn>
const mockMfaSetup        = authApi.mfaSetup        as ReturnType<typeof vi.fn>
const mockMfaVerifySetup  = authApi.mfaVerifySetup  as ReturnType<typeof vi.fn>
const mockQrToDataURL     = (QRCode as unknown as { toDataURL: ReturnType<typeof vi.fn> }).toDataURL

// ---------------------------------------------------------------------------
// Fixture data
// ---------------------------------------------------------------------------

const SETUP_DATA = {
  secret:       'JBSWY3DPEBLW64TMMQ',
  qr_code_uri:  'otpauth://totp/user@mxtac.local?secret=JBSWY3DPEBLW64TMMQ',
  backup_codes: ['AB12CD34', 'EF56GH78', 'IJ90KL12', 'MN34OP56', 'QR78ST90', 'UV12WX34', 'YZ56AB78', 'CD90EF12'],
}

// ---------------------------------------------------------------------------
// Render helper
// ---------------------------------------------------------------------------

function renderModal(onClose = vi.fn()) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: Infinity } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <MfaSetupModal onClose={onClose} />
    </QueryClientProvider>,
  )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('MfaSetupModal', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    // Default: QR code generation resolves with a data URL
    mockQrToDataURL.mockResolvedValue('data:image/png;base64,MOCK_QR')
  })

  // =========================================================================
  // Header — always visible
  // =========================================================================
  describe('header', () => {
    beforeEach(() => {
      mockMe.mockReturnValue(new Promise<never>(() => {}))
    })

    it('renders the "Security Settings" heading', () => {
      renderModal()
      expect(screen.getByText('Security Settings')).toBeInTheDocument()
    })

    it('renders the "Multi-Factor Authentication" subtitle', () => {
      renderModal()
      expect(screen.getByText('Multi-Factor Authentication')).toBeInTheDocument()
    })

    it('renders a close button (×)', () => {
      renderModal()
      expect(screen.getByRole('button', { name: '×' })).toBeInTheDocument()
    })

    it('calls onClose when the × button is clicked', () => {
      const onClose = vi.fn()
      renderModal(onClose)
      fireEvent.click(screen.getByRole('button', { name: '×' }))
      expect(onClose).toHaveBeenCalled()
    })

    it('calls onClose when the overlay backdrop is clicked', () => {
      const onClose = vi.fn()
      const { container } = renderModal(onClose)
      // The outer overlay div is the first child of the container
      const overlay = container.firstChild as HTMLElement
      fireEvent.click(overlay)
      expect(onClose).toHaveBeenCalled()
    })
  })

  // =========================================================================
  // Status step — loading
  // =========================================================================
  describe('status step — loading', () => {
    it('shows loading indicator while fetching MFA status', () => {
      mockMe.mockReturnValue(new Promise<never>(() => {}))
      renderModal()
      expect(screen.getByText('Loading…')).toBeInTheDocument()
    })
  })

  // =========================================================================
  // Status step — MFA enabled
  // =========================================================================
  describe('status step — MFA already enabled', () => {
    beforeEach(() => {
      mockMe.mockResolvedValue({ email: 'u@mxtac.local', role: 'analyst', full_name: null, mfa_enabled: true })
    })

    it('shows the "MFA is active" message', async () => {
      renderModal()
      await waitFor(() => expect(screen.getByText('MFA is active')).toBeInTheDocument())
    })

    it('shows a description about the account being protected', async () => {
      renderModal()
      await waitFor(() =>
        expect(screen.getByText(/Your account is protected with an authenticator app/)).toBeInTheDocument(),
      )
    })

    it('shows a note to contact admin to disable', async () => {
      renderModal()
      await waitFor(() =>
        expect(screen.getByText(/To disable MFA, contact an administrator/)).toBeInTheDocument(),
      )
    })

    it('renders a Close button', async () => {
      renderModal()
      await waitFor(() => expect(screen.getByRole('button', { name: 'Close' })).toBeInTheDocument())
    })

    it('does not render the "Enable MFA" button when MFA is already active', async () => {
      renderModal()
      await waitFor(() =>
        expect(screen.queryByRole('button', { name: 'Enable MFA' })).not.toBeInTheDocument(),
      )
    })

    it('calls onClose when the Close button is clicked', async () => {
      const onClose = vi.fn()
      renderModal(onClose)
      const btn = await screen.findByRole('button', { name: 'Close' })
      fireEvent.click(btn)
      expect(onClose).toHaveBeenCalled()
    })
  })

  // =========================================================================
  // Status step — MFA not configured
  // =========================================================================
  describe('status step — MFA not configured', () => {
    beforeEach(() => {
      mockMe.mockResolvedValue({ email: 'u@mxtac.local', role: 'analyst', full_name: null, mfa_enabled: false })
    })

    it('shows the "MFA not configured" message', async () => {
      renderModal()
      await waitFor(() => expect(screen.getByText('MFA not configured')).toBeInTheDocument())
    })

    it('shows an explanation about adding extra security', async () => {
      renderModal()
      await waitFor(() =>
        expect(screen.getByText(/Add an extra layer of security to your account/)).toBeInTheDocument(),
      )
    })

    it('renders the "Enable MFA" button', async () => {
      renderModal()
      await waitFor(() => expect(screen.getByRole('button', { name: 'Enable MFA' })).toBeInTheDocument())
    })

    it('renders the Cancel button', async () => {
      renderModal()
      await waitFor(() => expect(screen.getByRole('button', { name: 'Cancel' })).toBeInTheDocument())
    })

    it('calls onClose when Cancel is clicked', async () => {
      const onClose = vi.fn()
      renderModal(onClose)
      const btn = await screen.findByRole('button', { name: 'Cancel' })
      fireEvent.click(btn)
      expect(onClose).toHaveBeenCalled()
    })
  })

  // =========================================================================
  // Setup step — initiated by "Enable MFA"
  // =========================================================================
  describe('setup step', () => {
    beforeEach(() => {
      mockMe.mockResolvedValue({ email: 'u@mxtac.local', role: 'analyst', full_name: null, mfa_enabled: false })
      mockMfaSetup.mockResolvedValue(SETUP_DATA)
    })

    async function reachSetupStep() {
      renderModal()
      const btn = await screen.findByRole('button', { name: 'Enable MFA' })
      fireEvent.click(btn)
      await waitFor(() => expect(screen.getByText(/Scan this QR code/)).toBeInTheDocument())
    }

    it('calls authApi.mfaSetup when "Enable MFA" is clicked', async () => {
      await reachSetupStep()
      expect(mockMfaSetup).toHaveBeenCalledTimes(1)
    })

    it('shows the setup instructions', async () => {
      await reachSetupStep()
      expect(screen.getByText(/Scan this QR code with your authenticator app/)).toBeInTheDocument()
    })

    it('renders a QR code image once generated', async () => {
      await reachSetupStep()
      await waitFor(() => {
        const img = screen.getByRole('img', { name: 'MFA QR code' })
        expect(img).toBeInTheDocument()
        expect(img).toHaveAttribute('src', 'data:image/png;base64,MOCK_QR')
      })
    })

    it('shows the manual entry secret', async () => {
      await reachSetupStep()
      expect(screen.getByText(SETUP_DATA.secret)).toBeInTheDocument()
    })

    it('renders the "Manual entry key" label', async () => {
      await reachSetupStep()
      expect(screen.getByText('Manual entry key')).toBeInTheDocument()
    })

    it('renders a Copy button for the secret', async () => {
      await reachSetupStep()
      expect(screen.getByRole('button', { name: 'Copy' })).toBeInTheDocument()
    })

    it('renders the verification code input', async () => {
      await reachSetupStep()
      expect(screen.getByPlaceholderText('000000')).toBeInTheDocument()
    })

    it('renders the "Verification code" label', async () => {
      await reachSetupStep()
      expect(screen.getByText('Verification code')).toBeInTheDocument()
    })

    it('renders the "Verify & Enable" button', async () => {
      await reachSetupStep()
      expect(screen.getByRole('button', { name: 'Verify & Enable' })).toBeInTheDocument()
    })

    it('"Verify & Enable" is disabled until 6 digits are entered', async () => {
      await reachSetupStep()
      const btn = screen.getByRole('button', { name: 'Verify & Enable' })
      expect(btn).toBeDisabled()
    })

    it('"Verify & Enable" becomes enabled when 6 digits are entered', async () => {
      await reachSetupStep()
      fireEvent.change(screen.getByPlaceholderText('000000'), { target: { value: '123456' } })
      expect(screen.getByRole('button', { name: 'Verify & Enable' })).not.toBeDisabled()
    })

    it('strips non-numeric characters from the code input', async () => {
      await reachSetupStep()
      const input = screen.getByPlaceholderText('000000') as HTMLInputElement
      fireEvent.change(input, { target: { value: '12abc34' } })
      // Only digits should remain
      expect(input.value).toBe('1234')
    })

    it('renders the Back button', async () => {
      await reachSetupStep()
      expect(screen.getByRole('button', { name: 'Back' })).toBeInTheDocument()
    })

    it('clicking Back returns to the status step', async () => {
      await reachSetupStep()
      fireEvent.click(screen.getByRole('button', { name: 'Back' }))
      await waitFor(() => expect(screen.queryByText(/Scan this QR code/)).not.toBeInTheDocument())
    })

    it('shows "Generating…" on the Enable MFA button while setup is loading', async () => {
      // slow down mfaSetup so we can catch the pending state
      let settle!: () => void
      mockMfaSetup.mockImplementationOnce(
        () => new Promise<typeof SETUP_DATA>((resolve) => { settle = () => resolve(SETUP_DATA) }),
      )
      renderModal()
      const btn = await screen.findByRole('button', { name: 'Enable MFA' })
      fireEvent.click(btn)
      // Wait for react-query to update isPending and re-render the component
      await waitFor(() =>
        expect(screen.getByRole('button', { name: 'Generating…' })).toBeInTheDocument(),
      )
      settle()
    })
  })

  // =========================================================================
  // Setup step — verification submission
  // =========================================================================
  describe('setup step — verify submission', () => {
    beforeEach(() => {
      mockMe.mockResolvedValue({ email: 'u@mxtac.local', role: 'analyst', full_name: null, mfa_enabled: false })
      mockMfaSetup.mockResolvedValue(SETUP_DATA)
    })

    async function reachSetupStepWithCode(code = '123456') {
      renderModal()
      const enableBtn = await screen.findByRole('button', { name: 'Enable MFA' })
      fireEvent.click(enableBtn)
      await waitFor(() => expect(screen.getByPlaceholderText('000000')).toBeInTheDocument())
      fireEvent.change(screen.getByPlaceholderText('000000'), { target: { value: code } })
    }

    it('calls authApi.mfaVerifySetup with the entered code on form submit', async () => {
      mockMfaVerifySetup.mockResolvedValue({ message: 'MFA enabled' })
      await reachSetupStepWithCode('654321')

      const form = screen.getByRole('button', { name: 'Verify & Enable' }).closest('form')!
      fireEvent.submit(form)

      await waitFor(() => expect(mockMfaVerifySetup).toHaveBeenCalledWith('654321'))
    })

    it('advances to backup-codes step on successful verification', async () => {
      mockMfaVerifySetup.mockResolvedValue({ message: 'MFA enabled' })
      await reachSetupStepWithCode()

      const form = screen.getByRole('button', { name: 'Verify & Enable' }).closest('form')!
      fireEvent.submit(form)

      await waitFor(() =>
        expect(screen.getByText('MFA enabled successfully')).toBeInTheDocument(),
      )
    })

    it('shows an error message when verification fails', async () => {
      mockMfaVerifySetup.mockRejectedValue({
        response: { data: { detail: 'Invalid TOTP code' } },
      })
      await reachSetupStepWithCode()

      const form = screen.getByRole('button', { name: 'Verify & Enable' }).closest('form')!
      fireEvent.submit(form)

      await waitFor(() => expect(screen.getByText('Invalid TOTP code')).toBeInTheDocument())
    })

    it('shows "Invalid code" fallback when error has no detail', async () => {
      mockMfaVerifySetup.mockRejectedValue(new Error('Network error'))
      await reachSetupStepWithCode()

      const form = screen.getByRole('button', { name: 'Verify & Enable' }).closest('form')!
      fireEvent.submit(form)

      await waitFor(() => expect(screen.getByText('Invalid code')).toBeInTheDocument())
    })
  })

  // =========================================================================
  // Backup codes step
  // =========================================================================
  describe('backup codes step', () => {
    beforeEach(() => {
      mockMe.mockResolvedValue({ email: 'u@mxtac.local', role: 'analyst', full_name: null, mfa_enabled: false })
      mockMfaSetup.mockResolvedValue(SETUP_DATA)
      mockMfaVerifySetup.mockResolvedValue({ message: 'MFA enabled' })
    })

    async function reachBackupStep() {
      renderModal()
      const enableBtn = await screen.findByRole('button', { name: 'Enable MFA' })
      fireEvent.click(enableBtn)
      await waitFor(() => expect(screen.getByPlaceholderText('000000')).toBeInTheDocument())
      fireEvent.change(screen.getByPlaceholderText('000000'), { target: { value: '123456' } })
      const form = screen.getByRole('button', { name: 'Verify & Enable' }).closest('form')!
      fireEvent.submit(form)
      await waitFor(() => expect(screen.getByText('MFA enabled successfully')).toBeInTheDocument())
    }

    it('shows the success banner', async () => {
      await reachBackupStep()
      expect(screen.getByText('MFA enabled successfully')).toBeInTheDocument()
    })

    it('renders "Save your backup codes" heading', async () => {
      await reachBackupStep()
      expect(screen.getByText('Save your backup codes')).toBeInTheDocument()
    })

    it('renders all 8 backup codes', async () => {
      await reachBackupStep()
      for (const code of SETUP_DATA.backup_codes) {
        expect(screen.getByText(code)).toBeInTheDocument()
      }
    })

    it('renders the "Copy all" button', async () => {
      await reachBackupStep()
      expect(screen.getByRole('button', { name: 'Copy all' })).toBeInTheDocument()
    })

    it('renders the "Download .txt" button', async () => {
      await reachBackupStep()
      expect(screen.getByRole('button', { name: 'Download .txt' })).toBeInTheDocument()
    })

    it('renders the "Done" button', async () => {
      await reachBackupStep()
      expect(screen.getByRole('button', { name: 'Done' })).toBeInTheDocument()
    })

    it('calls onClose when Done is clicked', async () => {
      const onClose = vi.fn()
      mockMe.mockResolvedValue({ email: 'u@mxtac.local', role: 'analyst', full_name: null, mfa_enabled: false })
      mockMfaSetup.mockResolvedValue(SETUP_DATA)
      mockMfaVerifySetup.mockResolvedValue({ message: 'MFA enabled' })

      const queryClient = new QueryClient({
        defaultOptions: { queries: { retry: false, staleTime: Infinity } },
      })
      render(
        <QueryClientProvider client={queryClient}>
          <MfaSetupModal onClose={onClose} />
        </QueryClientProvider>,
      )

      const enableBtn = await screen.findByRole('button', { name: 'Enable MFA' })
      fireEvent.click(enableBtn)
      await waitFor(() => expect(screen.getByPlaceholderText('000000')).toBeInTheDocument())
      fireEvent.change(screen.getByPlaceholderText('000000'), { target: { value: '123456' } })
      const form = screen.getByRole('button', { name: 'Verify & Enable' }).closest('form')!
      fireEvent.submit(form)
      await waitFor(() => expect(screen.getByRole('button', { name: 'Done' })).toBeInTheDocument())

      fireEvent.click(screen.getByRole('button', { name: 'Done' }))
      expect(onClose).toHaveBeenCalled()
    })
  })

  // =========================================================================
  // Setup mutation error (step 1)
  // =========================================================================
  describe('setup mutation error', () => {
    beforeEach(() => {
      mockMe.mockResolvedValue({ email: 'u@mxtac.local', role: 'analyst', full_name: null, mfa_enabled: false })
    })

    it('shows an error banner when mfaSetup fails', async () => {
      mockMfaSetup.mockRejectedValue({
        response: { data: { detail: 'Setup failed: server error' } },
      })

      renderModal()
      const btn = await screen.findByRole('button', { name: 'Enable MFA' })
      fireEvent.click(btn)

      await waitFor(() =>
        expect(screen.getByText('Setup failed: server error')).toBeInTheDocument(),
      )
    })

    it('shows "Setup failed" fallback when no detail in error', async () => {
      mockMfaSetup.mockRejectedValue(new Error('Network error'))

      renderModal()
      const btn = await screen.findByRole('button', { name: 'Enable MFA' })
      fireEvent.click(btn)

      await waitFor(() => expect(screen.getByText('Setup failed')).toBeInTheDocument())
    })
  })
})
