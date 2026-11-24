import { useState, useEffect, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import QRCode from 'qrcode'
import { CircleAlert, CircleCheck } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
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
      .catch(() => setQrDataUrl(''))
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
      <div className="max-h-[90vh] w-[440px] max-w-[92vw] overflow-y-auto rounded-lg border border-border bg-card shadow-xl">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-border">
          <div>
            <h2 className="text-[13px] font-semibold text-foreground">Security Settings</h2>
            <p className="text-[11px] text-muted-foreground mt-0.5">Multi-Factor Authentication</p>
          </div>
          <Button variant="ghost" size="icon" title="Close" onClick={onClose} className="text-lg leading-none text-muted-foreground">
            ×
          </Button>
        </div>

        {/* Body */}
        <div className="px-5 py-4">

          {/* ── Status step ─────────────────────────────────────── */}
          {step === 'status' && (
            <>
              {meLoading ? (
                <div className="flex items-center justify-center h-20 text-[12px] text-muted-foreground">
                  Loading…
                </div>
              ) : me?.mfa_enabled ? (
                <div className="space-y-4">
                  <div className="flex items-center gap-3 rounded-md border status-green p-3">
                    <CircleCheck className="h-4 w-4 shrink-0" />
                    <div>
                      <div className="text-[12px] font-medium text-foreground">MFA is active</div>
                      <div className="text-[11px] text-muted-foreground mt-0.5">
                        Your account is protected with an authenticator app.
                      </div>
                    </div>
                  </div>
                  <p className="text-[11px] text-muted-foreground">
                    To disable MFA, contact an administrator.
                  </p>
                  <div className="flex justify-end">
                    <Button variant="outline" onClick={onClose}>Close</Button>
                  </div>
                </div>
              ) : (
                <div className="space-y-4">
                  <div className="flex items-center gap-3 rounded-md border sev-medium p-3">
                    <CircleAlert className="h-4 w-4 shrink-0" />
                    <div>
                      <div className="text-[12px] font-medium text-foreground">MFA not configured</div>
                      <div className="text-[11px] text-muted-foreground mt-0.5">
                        Add an extra layer of security to your account.
                      </div>
                    </div>
                  </div>

                  <p className="text-[11px] text-muted-foreground leading-relaxed">
                    Enabling MFA requires an authenticator app such as Google Authenticator,
                    Authy, or 1Password. After setup, you'll also receive backup codes in case
                    you lose access to your device.
                  </p>

                  {setupMutation.isError && (
                    <div className="rounded-md border sev-critical px-3 py-2 text-[11px]">
                      {(setupMutation.error as { response?: { data?: { detail?: string } } })
                        ?.response?.data?.detail ?? 'Setup failed'}
                    </div>
                  )}

                  <div className="flex justify-end gap-2">
                    <Button variant="outline" onClick={onClose}>Cancel</Button>
                    <Button onClick={() => setupMutation.mutate()} disabled={setupMutation.isPending}>
                      {setupMutation.isPending ? 'Generating…' : 'Enable MFA'}
                    </Button>
                  </div>
                </div>
              )}
            </>
          )}

          {/* ── Setup step: QR code + verify ────────────────────── */}
          {step === 'setup' && setupData && (
            <form onSubmit={handleVerifySubmit} className="space-y-4">
              <p className="text-[12px] text-foreground/80 leading-relaxed">
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
                  <div className="w-[180px] h-[180px] flex items-center justify-center bg-background border border-border rounded text-[11px] text-muted-foreground">
                    Loading QR…
                  </div>
                )}
              </div>

              {/* Manual entry secret */}
              <div>
                <Label className="mb-1 block text-[12px] font-medium">Manual entry key</Label>
                <div className="flex items-center gap-2">
                  <code className="flex-1 text-[11px] font-mono bg-background border border-border rounded px-2 py-1.5 text-foreground tracking-widest select-all">
                    {setupData.secret}
                  </code>
                  <Button type="button" variant="outline" onClick={handleCopySecret}>
                    {copied ? 'Copied!' : 'Copy'}
                  </Button>
                </div>
              </div>

              {/* Verification code input */}
              <div>
                <Label htmlFor="mfa-verify-code" className="mb-1 block text-[12px] font-medium">Verification code</Label>
                <Input
                  id="mfa-verify-code"
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
                  className="h-9 text-center font-mono text-sm tracking-widest"
                />
                {verifyError && (
                  <p className="mt-1 text-[11px] text-destructive">{verifyError}</p>
                )}
              </div>

              <div className="flex justify-end gap-2">
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => { setStep('status'); setSetupData(null); setQrDataUrl(''); setVerifyCode('') }}
                >
                  Back
                </Button>
                <Button type="submit" disabled={verifyCode.length < 6 || verifyMutation.isPending}>
                  {verifyMutation.isPending ? 'Verifying…' : 'Verify & Enable'}
                </Button>
              </div>
            </form>
          )}

          {/* ── Backup codes step ───────────────────────────────── */}
          {step === 'backup-codes' && setupData && (
            <div className="space-y-4">
              <div className="flex items-center gap-2 rounded-md border status-green p-3">
                <CircleCheck className="h-4 w-4 shrink-0" />
                <span className="text-[12px] font-medium text-foreground">MFA enabled successfully</span>
              </div>

              <div>
                <p className="text-[12px] font-medium text-foreground mb-1">Save your backup codes</p>
                <p className="text-[11px] text-muted-foreground leading-relaxed mb-3">
                  Store these in a safe place. Each code can only be used once if you lose access
                  to your authenticator app.
                </p>

                <div className="grid grid-cols-2 gap-1.5 p-3 bg-background border border-border rounded-md mb-3">
                  {setupData.backup_codes.map((code) => (
                    <code key={code} className="text-[11px] font-mono text-foreground tracking-widest text-center py-1">
                      {code}
                    </code>
                  ))}
                </div>

                <div className="flex gap-2">
                  <Button variant="outline" className="flex-1" onClick={handleCopyBackupCodes}>
                    {copied ? 'Copied!' : 'Copy all'}
                  </Button>
                  <Button variant="outline" className="flex-1" onClick={() => downloadBackupCodes(setupData.backup_codes)}>
                    Download .txt
                  </Button>
                </div>
              </div>

              <div className="flex justify-end">
                <Button onClick={onClose}>Done</Button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
