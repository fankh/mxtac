// vi.mock is hoisted before imports — declare all module mocks first.

vi.mock('../../lib/api', async (importOriginal) => {
  const actual = await importOriginal<typeof ApiModule>()
  return {
    ...actual,
    authApi: { ...actual.authApi, me: vi.fn(), mfaSetup: vi.fn(), mfaVerifySetup: vi.fn() },
  }
})

vi.mock('qrcode', () => ({ default: { toDataURL: vi.fn() } }))

vi.mock('../../lib/download', () => ({ downloadBlob: vi.fn() }))

import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import QRCode from 'qrcode'
import { MfaSetupModal } from '../../components/shared/MfaSetupModal'
import type * as ApiModule from '../../lib/api'
import { authApi } from '../../lib/api'
import { downloadBlob } from '../../lib/download'

const meMock = vi.mocked(authApi.me)
const setupMock = vi.mocked(authApi.mfaSetup)
const verifyMock = vi.mocked(authApi.mfaVerifySetup)
const downloadMock = vi.mocked(downloadBlob)
// The component uses the promise form of toDataURL; the overloads make vi.mocked pick the callback form.
const qrMock = QRCode.toDataURL as unknown as ReturnType<typeof vi.fn<(text: string) => Promise<string>>>

const SETUP_DATA = {
  secret: 'JBSWY3DPEBLW64TMMQ',
  qr_code_uri: 'otpauth://totp/user@mxtac.local?secret=JBSWY3DPEBLW64TMMQ',
  backup_codes: ['AB12CD34', 'EF56GH78', 'IJ90KL12', 'MN34OP56', 'QR78ST90', 'UV12WX34', 'YZ56AB78', 'CD90EF12'],
}

function profile(mfaEnabled: boolean) {
  return { email: 'u@mxtac.local', role: 'analyst', full_name: null, mfa_enabled: mfaEnabled }
}

function setup() {
  const onClose = vi.fn()
  const user = userEvent.setup()
  const writeText = vi.spyOn(navigator.clipboard, 'writeText').mockResolvedValue()
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={queryClient}>
      <MfaSetupModal onClose={onClose} />
    </QueryClientProvider>,
  )
  return { onClose, user, writeText }
}

/** jsdom's Blob has no text(); FileReader reads it instead. */
function readText(blob: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => resolve(String(reader.result))
    reader.onerror = () => reject(reader.error)
    reader.readAsText(blob)
  })
}

/** Opens the dialog and moves to the step with the QR code and the code field. */
async function openSetupStep() {
  const view = setup()
  await view.user.click(await screen.findByRole('button', { name: 'Enable MFA' }))
  await screen.findByLabelText('Verification code')
  return view
}

/** Completes enrolment so the backup codes are shown. */
async function openBackupCodesStep() {
  const view = await openSetupStep()
  await view.user.type(screen.getByLabelText('Verification code'), '123456')
  await view.user.click(screen.getByRole('button', { name: 'Verify & Enable' }))
  await screen.findByRole('list', { name: 'Backup codes' })
  return view
}

describe('MfaSetupModal', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    meMock.mockResolvedValue(profile(false))
    setupMock.mockResolvedValue(SETUP_DATA)
    verifyMock.mockResolvedValue({ message: 'MFA enabled' })
    qrMock.mockResolvedValue('data:image/png;base64,MOCK_QR')
  })

  describe('dialog', () => {
    it('is a dialog named by its title and described by its subtitle', async () => {
      setup()
      const dialog = await screen.findByRole('dialog', { name: 'Security Settings' })
      expect(dialog).toHaveAccessibleDescription('Multi-Factor Authentication')
    })

    it('shows a loading status until the MFA state is known', () => {
      meMock.mockReturnValue(new Promise<never>(() => {}))
      setup()
      expect(screen.getByRole('status')).toHaveTextContent('Loading…')
      expect(screen.queryByRole('button', { name: 'Enable MFA' })).not.toBeInTheDocument()
    })

    it('closes on Escape', async () => {
      const { onClose, user } = setup()
      await screen.findByRole('button', { name: 'Enable MFA' })
      await user.keyboard('{Escape}')
      expect(onClose).toHaveBeenCalledTimes(1)
    })

    it('closes on a click outside the dialog', async () => {
      const { onClose, user } = setup()
      const dialog = await screen.findByRole('dialog')
      await screen.findByRole('button', { name: 'Enable MFA' })
      // A click outside lands on the dimmed layer behind the dialog.
      const backdrop = dialog.previousElementSibling
      if (!backdrop) throw new Error('The dialog has no backdrop')
      await user.click(backdrop)
      expect(onClose).toHaveBeenCalledTimes(1)
    })

    it('does not close on a click inside the dialog', async () => {
      const { onClose, user } = setup()
      await screen.findByRole('button', { name: 'Enable MFA' })
      await user.click(screen.getByText('MFA not configured'))
      expect(onClose).not.toHaveBeenCalled()
    })

    it('closes from the corner close button', async () => {
      const { onClose, user } = setup()
      await screen.findByRole('button', { name: 'Enable MFA' })
      await user.click(screen.getByRole('button', { name: 'Close' }))
      expect(onClose).toHaveBeenCalledTimes(1)
    })

    it('keeps keyboard focus inside the dialog', async () => {
      const { user } = setup()
      const dialog = await screen.findByRole('dialog')
      await screen.findByRole('button', { name: 'Enable MFA' })
      for (let i = 0; i < 6; i++) {
        await user.tab()
        expect(dialog).toContainElement(document.activeElement as HTMLElement)
      }
    })
  })

  describe('when MFA is already enabled', () => {
    beforeEach(() => {
      meMock.mockResolvedValue(profile(true))
    })

    it('says so and offers no enrolment', async () => {
      setup()
      expect(await screen.findByText('MFA is active')).toBeInTheDocument()
      expect(screen.getByText(/Your account is protected with an authenticator app/)).toBeInTheDocument()
      expect(screen.getByText(/To disable MFA, contact an administrator/)).toBeInTheDocument()
      expect(screen.queryByRole('button', { name: 'Enable MFA' })).not.toBeInTheDocument()
    })

    it('closes from either Close button', async () => {
      const { onClose, user } = setup()
      await screen.findByText('MFA is active')
      const closeButtons = screen.getAllByRole('button', { name: 'Close' })
      expect(closeButtons).toHaveLength(2)
      for (const button of closeButtons) await user.click(button)
      expect(onClose).toHaveBeenCalledTimes(2)
    })
  })

  describe('when MFA is not configured', () => {
    it('explains MFA and offers to enable it', async () => {
      setup()
      expect(await screen.findByText('MFA not configured')).toBeInTheDocument()
      expect(screen.getByText(/Add an extra layer of security to your account/)).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Enable MFA' })).toBeEnabled()
      expect(setupMock).not.toHaveBeenCalled()
    })

    it('closes on Cancel', async () => {
      const { onClose, user } = setup()
      await user.click(await screen.findByRole('button', { name: 'Cancel' }))
      expect(onClose).toHaveBeenCalledTimes(1)
    })

    it('disables the button and shows progress while the secret is generated', async () => {
      let finish: (data: typeof SETUP_DATA) => void = () => {}
      setupMock.mockReturnValueOnce(new Promise((resolve) => { finish = resolve }))
      const { user } = setup()
      await user.click(await screen.findByRole('button', { name: 'Enable MFA' }))

      expect(await screen.findByRole('button', { name: 'Generating…' })).toBeDisabled()

      finish(SETUP_DATA)
      expect(await screen.findByLabelText('Verification code')).toBeInTheDocument()
    })

    it('shows the server message as an alert when setup fails', async () => {
      setupMock.mockRejectedValue({ response: { data: { detail: 'Setup failed: server error' } } })
      const { user } = setup()
      await user.click(await screen.findByRole('button', { name: 'Enable MFA' }))

      expect(await screen.findByRole('alert')).toHaveTextContent('Setup failed: server error')
      expect(screen.getByRole('button', { name: 'Enable MFA' })).toBeEnabled()
    })

    it('shows "Setup failed" when the failure has no server message', async () => {
      setupMock.mockRejectedValue(new Error('Network error'))
      const { user } = setup()
      await user.click(await screen.findByRole('button', { name: 'Enable MFA' }))

      expect(await screen.findByRole('alert')).toHaveTextContent('Setup failed')
    })
  })

  describe('setup step', () => {
    it('requests a secret once and draws its QR code', async () => {
      await openSetupStep()

      expect(setupMock).toHaveBeenCalledTimes(1)
      expect(screen.getByText(/Scan this QR code with your authenticator app/)).toBeInTheDocument()
      const qr = await screen.findByRole('img', { name: 'MFA QR code' })
      expect(qr).toHaveAttribute('src', 'data:image/png;base64,MOCK_QR')
      expect(qrMock).toHaveBeenCalledWith(SETUP_DATA.qr_code_uri, expect.anything())
    })

    it('shows a placeholder while the QR code is drawn', async () => {
      qrMock.mockReturnValue(new Promise<never>(() => {}))
      await openSetupStep()

      expect(screen.getByRole('status')).toHaveTextContent('Loading QR…')
      expect(screen.queryByRole('img', { name: 'MFA QR code' })).not.toBeInTheDocument()
    })

    it('keeps the manual key usable when the QR code cannot be drawn', async () => {
      qrMock.mockRejectedValue(new Error('canvas unavailable'))
      await openSetupStep()

      expect(within(screen.getByRole('group', { name: 'Manual entry key' })).getByText(SETUP_DATA.secret)).toBeInTheDocument()
      expect(screen.queryByRole('img', { name: 'MFA QR code' })).not.toBeInTheDocument()
    })

    it('copies the manual key and confirms it on the button', async () => {
      const { user, writeText } = await openSetupStep()
      const group = screen.getByRole('group', { name: 'Manual entry key' })
      expect(within(group).getByText(SETUP_DATA.secret)).toBeInTheDocument()

      await user.click(within(group).getByRole('button', { name: 'Copy' }))

      expect(writeText).toHaveBeenCalledWith(SETUP_DATA.secret)
      expect(within(group).getByRole('button', { name: 'Copied!' })).toBeInTheDocument()
    })

    it('puts the focus in the code field', async () => {
      await openSetupStep()
      expect(screen.getByLabelText('Verification code')).toHaveFocus()
    })

    it('accepts digits only, at most six', async () => {
      const { user } = await openSetupStep()
      const input = screen.getByLabelText('Verification code')

      await user.type(input, '12ab-34')
      expect(input).toHaveValue('1234')

      await user.type(input, '56789')
      expect(input).toHaveValue('123456')
    })

    it('enables verification only once six digits are entered', async () => {
      const { user } = await openSetupStep()
      const verify = screen.getByRole('button', { name: 'Verify & Enable' })
      expect(verify).toBeDisabled()

      await user.type(screen.getByLabelText('Verification code'), '12345')
      expect(verify).toBeDisabled()

      await user.type(screen.getByLabelText('Verification code'), '6')
      expect(verify).toBeEnabled()
    })

    it('goes back to the start and forgets the secret', async () => {
      const { user } = await openSetupStep()
      await user.click(screen.getByRole('button', { name: 'Back' }))

      expect(await screen.findByRole('button', { name: 'Enable MFA' })).toBeInTheDocument()
      expect(screen.queryByText(SETUP_DATA.secret)).not.toBeInTheDocument()
      expect(screen.queryByLabelText('Verification code')).not.toBeInTheDocument()
    })
  })

  describe('verification', () => {
    it('sends the code when the button is clicked', async () => {
      const { user } = await openSetupStep()
      await user.type(screen.getByLabelText('Verification code'), '654321')
      await user.click(screen.getByRole('button', { name: 'Verify & Enable' }))

      await waitFor(() => expect(verifyMock).toHaveBeenCalledWith('654321'))
    })

    it('sends the code when Enter is pressed in the field', async () => {
      const { user } = await openSetupStep()
      await user.type(screen.getByLabelText('Verification code'), '654321{Enter}')

      await waitFor(() => expect(verifyMock).toHaveBeenCalledWith('654321'))
    })

    it('does not send an incomplete code on Enter', async () => {
      const { user } = await openSetupStep()
      await user.type(screen.getByLabelText('Verification code'), '123{Enter}')

      expect(verifyMock).not.toHaveBeenCalled()
    })

    it('shows the server message on the field when the code is rejected', async () => {
      verifyMock.mockRejectedValue({ response: { data: { detail: 'Invalid TOTP code' } } })
      const { user } = await openSetupStep()
      const input = screen.getByLabelText('Verification code')
      await user.type(input, '123456{Enter}')

      expect(await screen.findByRole('alert')).toHaveTextContent('Invalid TOTP code')
      expect(input).toBeInvalid()
      expect(input).toHaveAccessibleDescription('Invalid TOTP code')
      expect(screen.queryByRole('list', { name: 'Backup codes' })).not.toBeInTheDocument()
    })

    it('shows "Invalid code" when the failure has no server message', async () => {
      verifyMock.mockRejectedValue(new Error('Network error'))
      const { user } = await openSetupStep()
      await user.type(screen.getByLabelText('Verification code'), '123456{Enter}')

      expect(await screen.findByRole('alert')).toHaveTextContent('Invalid code')
    })

    it('clears the error when the code is edited', async () => {
      verifyMock.mockRejectedValue(new Error('Network error'))
      const { user } = await openSetupStep()
      const input = screen.getByLabelText('Verification code')
      await user.type(input, '123456{Enter}')
      await screen.findByRole('alert')

      await user.type(input, '{Backspace}')

      expect(screen.queryByRole('alert')).not.toBeInTheDocument()
      expect(input).toBeValid()
    })

    it('refreshes the profile after a successful verification', async () => {
      await openBackupCodesStep()
      await waitFor(() => expect(meMock).toHaveBeenCalledTimes(2))
    })
  })

  describe('backup codes step', () => {
    it('confirms that MFA is on and lists every backup code', async () => {
      await openBackupCodesStep()

      expect(screen.getByRole('status')).toHaveTextContent('MFA enabled successfully')
      expect(screen.getByRole('heading', { name: 'Save your backup codes' })).toBeInTheDocument()
      const codes = within(screen.getByRole('list', { name: 'Backup codes' })).getAllByRole('listitem')
      expect(codes.map((item) => item.textContent)).toEqual(SETUP_DATA.backup_codes)
    })

    it('copies all codes, one per line, and confirms it on the button', async () => {
      const { user, writeText } = await openBackupCodesStep()
      await user.click(screen.getByRole('button', { name: 'Copy all' }))

      expect(writeText).toHaveBeenCalledWith(SETUP_DATA.backup_codes.join('\n'))
      expect(screen.getByRole('button', { name: 'Copied!' })).toBeInTheDocument()
    })

    it('downloads the codes as a text file', async () => {
      const { user } = await openBackupCodesStep()
      await user.click(screen.getByRole('button', { name: 'Download .txt' }))

      expect(downloadMock).toHaveBeenCalledTimes(1)
      const [blob, filename] = downloadMock.mock.calls[0]
      expect(filename).toBe('mxtac-backup-codes.txt')
      expect(blob.type).toBe('text/plain')
      const text = await readText(blob)
      for (const code of SETUP_DATA.backup_codes) expect(text).toContain(code)
    })

    it('closes on Done', async () => {
      const { onClose, user } = await openBackupCodesStep()
      await user.click(screen.getByRole('button', { name: 'Done' }))
      expect(onClose).toHaveBeenCalledTimes(1)
    })
  })
})
