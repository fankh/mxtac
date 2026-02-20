import { useState, useEffect, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import QRCode from 'qrcode'
import { authApi } from '../../../lib/api'

interface Props {
  onClose: () => void
}

type Step = 'status' | 'setup' | 'backup-codes'

function copyToClipboard(text: string) {
  navigator.clipboard.writeText(text).catch(() => {
    const el = document.createElement('textarea')
    el.value = text
    document.body.appendChild(el)
    el.select()
    document.execCommand('copy')
    document.body.removeChild(el)
  })
}

function downloadBackupCodes(codes: string[]) {
  const content = [
    'MxTac MFA Backup Codes',
    '======================',
    'Keep these codes safe. Each code can only be used once.',
    '',
    ...codes,
    '',
    `Generated: ${new Date().toISOString()}`,
  ].join('\n')
  const blob = new Blob([content], { type: 'text/plain' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = 'mxtac-backup-codes.txt'
  a.click()
  URL.revokeObjectURL(url)
}

export function MfaSetupModal({ onClose }: Props) {
  const queryClient = useQueryClient()
  const overlayRef = useRef<HTMLDivElement>(null)

  const [step, setStep] = useState<Step>('status')
  const [qrDataUrl, setQrDataUrl] = useState<string>('')
  const [setupData, setSetupData] = useState<{
    secret: string
    qr_code_uri: string
    backup_codes: string[]
  } | null>(null)
  const [verifyCode, setVerifyCode] = useState('')
  const [verifyError, setVerifyError] = useState('')
  const [copied, setCopied] = useState(false)

  // Fetch current MFA status
  const { data: me, isLoading: meLoading } = useQuery({
    queryKey: ['auth-me'],
    queryFn: authApi.me,
  })

  // Generate QR code data URL when setup data arrives
  useEffect(() => {
    if (!setupData?.qr_code_uri) return
    QRCode.toDataURL(setupData.qr_code_uri, { width: 200, margin: 1, color: { dark: '#000000', light: '#ffffff' } })
      .then(setQrDataUrl)
      .catch(console.error)
  }, [setupData?.qr_code_uri])

  // Initiate MFA setup (generates secret + QR)
  const setupMutation = useMutation({
    mutationFn: authApi.mfaSetup,
    onSuccess: (data) => {
      setSetupData(data)
      setStep('setup')
    },
  })

  // Verify TOTP code to activate MFA
  const verifyMutation = useMutation({
    mutationFn: () => authApi.mfaVerifySetup(verifyCode.trim()),
    onSuccess: () => {
      setVerifyError('')
      setStep('backup-codes')
      // Invalidate me query so next open shows MFA enabled
      queryClient.invalidateQueries({ queryKey: ['auth-me'] })
    },
    onError: (err: unknown) => {
      const detail = (err as { response?: { data?: { detail?: string } } })
        ?.response?.data?.detail ?? 'Invalid code'
      setVerifyError(detail)
    },
  })

  function handleOverlayClick(e: React.MouseEvent) {
    if (e.target === overlayRef.current) onClose()
  }

  function handleVerifySubmit(e: React.FormEvent) {
    e.preventDefault()
    if (verifyCode.length < 6) return
    setVerifyError('')
    verifyMutation.mutate()
  }

  function handleCopySecret() {
    if (setupData?.secret) copyToClipboard(setupData.secret)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  function handleCopyBackupCodes() {
    if (setupData?.backup_codes) copyToClipboard(setupData.backup_codes.join('\n'))
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div
      ref={overlayRef}
      className="fixed inset-0 bg-black/50 flex items-center justify-center z-50"
      onClick={handleOverlayClick}
    >
      <div className="bg-surface rounded-lg shadow-panel w-[440px] max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-border">
          <div>
            <h2 className="text-[13px] font-semibold text-text-primary">Security Settings</h2>
            <p className="text-[11px] text-text-muted mt-0.5">Multi-Factor Authentication</p>
          </div>
          <button
            onClick={onClose}
            className="text-text-muted hover:text-text-primary text-lg leading-none"
          >
            ×
          </button>
        </div>

        {/* Body */}
        <div className="px-5 py-4">

          {/* ── Status step ─────────────────────────────────────── */}
          {step === 'status' && (
            <>
              {meLoading ? (
                <div className="flex items-center justify-center h-20 text-[12px] text-text-muted">
                  Loading…
                </div>
              ) : me?.mfa_enabled ? (
                <div className="space-y-4">
                  <div className="flex items-center gap-3 p-3 bg-status-ok/10 rounded-md border border-status-ok/30">
                    <span className="text-status-ok text-lg">✓</span>
                    <div>
                      <div className="text-[12px] font-medium text-text-primary">MFA is active</div>
                      <div className="text-[11px] text-text-muted mt-0.5">
                        Your account is protected with an authenticator app.
                      </div>
                    </div>
                  </div>
                  <p className="text-[11px] text-text-muted">
                    To disable MFA, contact an administrator.
                  </p>
                  <div className="flex justify-end">
                    <button
                      onClick={onClose}
                      className="h-[30px] px-4 text-[12px] bg-surface border border-border rounded-md text-text-secondary hover:bg-page"
                    >
                      Close
                    </button>
                  </div>
                </div>
              ) : (
                <div className="space-y-4">
                  <div className="flex items-center gap-3 p-3 bg-warn-bg rounded-md border border-warn-text/20">
                    <span className="text-warn-text text-lg">⚠</span>
                    <div>
                      <div className="text-[12px] font-medium text-text-primary">MFA not configured</div>
                      <div className="text-[11px] text-text-muted mt-0.5">
                        Add an extra layer of security to your account.
                      </div>
                    </div>
                  </div>

                  <p className="text-[11px] text-text-muted leading-relaxed">
                    Enabling MFA requires an authenticator app such as Google Authenticator,
                    Authy, or 1Password. After setup, you'll also receive backup codes in case
                    you lose access to your device.
                  </p>

                  {setupMutation.isError && (
                    <div className="text-xs text-crit-text bg-crit-bg rounded-md px-3 py-2">
                      {(setupMutation.error as { response?: { data?: { detail?: string } } })
                        ?.response?.data?.detail ?? 'Setup failed'}
                    </div>
                  )}

                  <div className="flex justify-end gap-2">
                    <button
                      onClick={onClose}
                      className="h-[30px] px-4 text-[12px] bg-surface border border-border rounded-md text-text-secondary hover:bg-page"
                    >
                      Cancel
                    </button>
                    <button
                      onClick={() => setupMutation.mutate()}
                      disabled={setupMutation.isPending}
                      className="h-[30px] px-4 text-[12px] bg-blue text-white rounded-md hover:opacity-90 disabled:opacity-50"
                    >
                      {setupMutation.isPending ? 'Generating…' : 'Enable MFA'}
                    </button>
                  </div>
                </div>
              )}
            </>
          )}

          {/* ── Setup step: QR code + verify ────────────────────── */}
          {step === 'setup' && setupData && (
            <form onSubmit={handleVerifySubmit} className="space-y-4">
              <p className="text-[12px] text-text-secondary leading-relaxed">
                Scan this QR code with your authenticator app, then enter the 6-digit code below.
              </p>

              {/* QR code */}
              <div className="flex flex-col items-center gap-3">
                {qrDataUrl ? (
                  <img
                    src={qrDataUrl}
                    alt="MFA QR code"
                    width={180}
                    height={180}
                    className="rounded border border-border p-1 bg-white"
                  />
                ) : (
                  <div className="w-[180px] h-[180px] flex items-center justify-center bg-page border border-border rounded text-[11px] text-text-muted">
                    Loading QR…
                  </div>
                )}
              </div>

              {/* Manual entry secret */}
              <div>
                <label className="block text-[10px] font-medium text-text-muted uppercase mb-1">
                  Manual entry key
                </label>
                <div className="flex items-center gap-2">
                  <code className="flex-1 text-[11px] font-mono bg-page border border-border rounded px-2 py-1.5 text-text-primary tracking-widest select-all">
                    {setupData.secret}
                  </code>
                  <button
                    type="button"
                    onClick={handleCopySecret}
                    className="h-[28px] px-2 text-[10px] bg-surface border border-border rounded hover:bg-page text-text-secondary whitespace-nowrap"
                  >
                    {copied ? 'Copied!' : 'Copy'}
                  </button>
                </div>
              </div>

              {/* Verification code input */}
              <div>
                <label className="block text-[10px] font-medium text-text-muted uppercase mb-1">
                  Verification code
                </label>
                <input
                  type="text"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  autoFocus
                  maxLength={6}
                  placeholder="000000"
                  value={verifyCode}
                  onChange={(e) => {
                    setVerifyCode(e.target.value.replace(/\D/g, ''))
                    setVerifyError('')
                  }}
                  className="w-full border border-border rounded-md px-3 py-2 text-sm text-center tracking-widest font-mono focus:outline-none focus:border-blue focus:ring-1 focus:ring-blue bg-page text-text-primary placeholder-text-muted"
                />
                {verifyError && (
                  <p className="text-[11px] text-crit-text mt-1">{verifyError}</p>
                )}
              </div>

              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => { setStep('status'); setSetupData(null); setQrDataUrl(''); setVerifyCode('') }}
                  className="h-[30px] px-4 text-[12px] bg-surface border border-border rounded-md text-text-secondary hover:bg-page"
                >
                  Back
                </button>
                <button
                  type="submit"
                  disabled={verifyCode.length < 6 || verifyMutation.isPending}
                  className="h-[30px] px-4 text-[12px] bg-blue text-white rounded-md hover:opacity-90 disabled:opacity-50"
                >
                  {verifyMutation.isPending ? 'Verifying…' : 'Verify & Enable'}
                </button>
              </div>
            </form>
          )}

          {/* ── Backup codes step ───────────────────────────────── */}
          {step === 'backup-codes' && setupData && (
            <div className="space-y-4">
              <div className="flex items-center gap-2 p-3 bg-status-ok/10 rounded-md border border-status-ok/30">
                <span className="text-status-ok">✓</span>
                <span className="text-[12px] font-medium text-text-primary">MFA enabled successfully</span>
              </div>

              <div>
                <p className="text-[12px] font-medium text-text-primary mb-1">Save your backup codes</p>
                <p className="text-[11px] text-text-muted leading-relaxed mb-3">
                  Store these in a safe place. Each code can only be used once if you lose access
                  to your authenticator app.
                </p>

                <div className="grid grid-cols-2 gap-1.5 p-3 bg-page border border-border rounded-md mb-3">
                  {setupData.backup_codes.map((code) => (
                    <code key={code} className="text-[11px] font-mono text-text-primary tracking-widest text-center py-1">
                      {code}
                    </code>
                  ))}
                </div>

                <div className="flex gap-2">
                  <button
                    onClick={handleCopyBackupCodes}
                    className="flex-1 h-[30px] text-[11px] bg-surface border border-border rounded-md text-text-secondary hover:bg-page"
                  >
                    {copied ? 'Copied!' : 'Copy all'}
                  </button>
                  <button
                    onClick={() => downloadBackupCodes(setupData.backup_codes)}
                    className="flex-1 h-[30px] text-[11px] bg-surface border border-border rounded-md text-text-secondary hover:bg-page"
                  >
                    Download .txt
                  </button>
                </div>
              </div>

              <div className="flex justify-end">
                <button
                  onClick={onClose}
                  className="h-[30px] px-5 text-[12px] bg-blue text-white rounded-md hover:opacity-90"
                >
                  Done
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
