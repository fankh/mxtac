import { useEffect, useId, useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import QRCode from 'qrcode'
import { CircleAlert, CircleCheck } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { apiErrorMessage, authApi } from '@/lib/api'
import { downloadBlob } from '@/lib/download'

interface Props {
  onClose: () => void
}

type Step = 'status' | 'setup' | 'backup-codes'

/** What was last copied, so only that button shows the confirmation. */
type Copied = 'secret' | 'backup-codes' | null

interface SetupData {
  secret: string
  qr_code_uri: string
  backup_codes: string[]
}

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
  downloadBlob(new Blob([content], { type: 'text/plain' }), 'mxtac-backup-codes.txt')
}

/**
 * Multi-factor authentication dialog: shows the current state, then walks through
 * enrolment (QR code or manual key, code check) and hands out the backup codes.
 * Mount it to open it; `onClose` fires on Escape, an outside click and every close button.
 */
export function MfaSetupModal({ onClose }: Props) {
  const queryClient = useQueryClient()
  const secretLabelId = useId()
  const codeErrorId = useId()

  const [step, setStep] = useState<Step>('status')
  const [qrDataUrl, setQrDataUrl] = useState('')
  const [setupData, setSetupData] = useState<SetupData | null>(null)
  const [verifyCode, setVerifyCode] = useState('')
  const [verifyError, setVerifyError] = useState('')
  const [copied, setCopied] = useState<Copied>(null)

  const { data: me, isLoading: meLoading } = useQuery({
    queryKey: ['auth-me'],
    queryFn: authApi.me,
  })

  // Draw the QR code once the enrolment secret has arrived.
  useEffect(() => {
    if (!setupData?.qr_code_uri) return
    QRCode.toDataURL(setupData.qr_code_uri, { width: 200, margin: 1, color: { dark: '#000000', light: '#ffffff' } })
      .then(setQrDataUrl)
      .catch(() => setQrDataUrl(''))
  }, [setupData?.qr_code_uri])

  // The "Copied!" confirmation goes back to the button label after two seconds.
  useEffect(() => {
    if (!copied) return
    const timer = setTimeout(() => setCopied(null), 2000)
    return () => clearTimeout(timer)
  }, [copied])

  const setupMutation = useMutation({
    mutationFn: authApi.mfaSetup,
    onSuccess: (data) => {
      setSetupData(data)
      setStep('setup')
    },
  })

  const verifyMutation = useMutation({
    mutationFn: () => authApi.mfaVerifySetup(verifyCode.trim()),
    onSuccess: () => {
      setVerifyError('')
      setCopied(null)
      setStep('backup-codes')
      // The next read of the profile must show MFA as enabled.
      queryClient.invalidateQueries({ queryKey: ['auth-me'] })
    },
    onError: (err: unknown) => setVerifyError(apiErrorMessage(err, 'Invalid code')),
  })

  function handleVerifySubmit(e: FormEvent) {
    e.preventDefault()
    if (verifyCode.length < 6) return
    setVerifyError('')
    verifyMutation.mutate()
  }

  function handleBack() {
    setStep('status')
    setSetupData(null)
    setQrDataUrl('')
    setVerifyCode('')
    setVerifyError('')
  }

  function handleCopySecret() {
    if (!setupData) return
    copyToClipboard(setupData.secret)
    setCopied('secret')
  }

  function handleCopyBackupCodes() {
    if (!setupData) return
    copyToClipboard(setupData.backup_codes.join('\n'))
    setCopied('backup-codes')
  }

  return (
    <Dialog open onOpenChange={(next) => { if (!next) onClose() }}>
      <DialogContent className="max-h-[90vh] max-w-md overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Security Settings</DialogTitle>
          <DialogDescription>Multi-Factor Authentication</DialogDescription>
        </DialogHeader>

        {step === 'status' && meLoading && (
          <p role="status" className="flex h-20 items-center justify-center text-[12px] text-muted-foreground">
            Loading…
          </p>
        )}

        {step === 'status' && !meLoading && me?.mfa_enabled && (
          <div className="space-y-4">
            <div className="flex items-center gap-3 rounded-md border status-green p-3">
              <CircleCheck className="h-4 w-4 shrink-0" />
              <div>
                <p className="text-[12px] font-medium text-foreground">MFA is active</p>
                <p className="mt-0.5 text-[11px] text-muted-foreground">
                  Your account is protected with an authenticator app.
                </p>
              </div>
            </div>
            <p className="text-[11px] text-muted-foreground">
              To disable MFA, contact an administrator.
            </p>
            <DialogFooter>
              <Button variant="outline" onClick={onClose}>Close</Button>
            </DialogFooter>
          </div>
        )}

        {step === 'status' && !meLoading && !me?.mfa_enabled && (
          <div className="space-y-4">
            <div className="flex items-center gap-3 rounded-md border sev-medium p-3">
              <CircleAlert className="h-4 w-4 shrink-0" />
              <div>
                <p className="text-[12px] font-medium text-foreground">MFA not configured</p>
                <p className="mt-0.5 text-[11px] text-muted-foreground">
                  Add an extra layer of security to your account.
                </p>
              </div>
            </div>

            <p className="text-[11px] leading-relaxed text-muted-foreground">
              Enabling MFA requires an authenticator app such as Google Authenticator,
              Authy, or 1Password. After setup, you&apos;ll also receive backup codes in case
              you lose access to your device.
            </p>

            {setupMutation.isError && (
              <p role="alert" className="rounded-md border sev-critical px-3 py-2 text-[11px]">
                {apiErrorMessage(setupMutation.error, 'Setup failed')}
              </p>
            )}

            <DialogFooter>
              <Button variant="outline" onClick={onClose}>Cancel</Button>
              <Button onClick={() => setupMutation.mutate()} disabled={setupMutation.isPending}>
                {setupMutation.isPending ? 'Generating…' : 'Enable MFA'}
              </Button>
            </DialogFooter>
          </div>
        )}

        {step === 'setup' && setupData && (
          <form onSubmit={handleVerifySubmit} className="space-y-4">
            <p className="text-[12px] leading-relaxed text-foreground/80">
              Scan this QR code with your authenticator app, then enter the 6-digit code below.
            </p>

            <div className="flex flex-col items-center gap-3">
              {qrDataUrl ? (
                <img
                  src={qrDataUrl}
                  alt="MFA QR code"
                  width={180}
                  height={180}
                  className="rounded border border-border bg-white p-1"
                />
              ) : (
                <div
                  role="status"
                  className="flex h-[180px] w-[180px] items-center justify-center rounded border border-border bg-background text-[11px] text-muted-foreground"
                >
                  Loading QR…
                </div>
              )}
            </div>

            <div role="group" aria-labelledby={secretLabelId}>
              <Label id={secretLabelId} className="mb-1 block text-[12px] font-medium">Manual entry key</Label>
              <div className="flex items-center gap-2">
                <code className="flex-1 select-all rounded border border-border bg-background px-2 py-1.5 font-mono text-[11px] tracking-widest text-foreground">
                  {setupData.secret}
                </code>
                <Button type="button" variant="outline" onClick={handleCopySecret}>
                  {copied === 'secret' ? 'Copied!' : 'Copy'}
                </Button>
              </div>
            </div>

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
                aria-invalid={verifyError ? true : undefined}
                aria-describedby={verifyError ? codeErrorId : undefined}
                onChange={(e) => {
                  setVerifyCode(e.target.value.replace(/\D/g, ''))
                  setVerifyError('')
                }}
                className="h-9 text-center font-mono text-sm tracking-widest"
              />
              {verifyError && (
                <p id={codeErrorId} role="alert" className="mt-1 text-[11px] text-destructive">{verifyError}</p>
              )}
            </div>

            <DialogFooter>
              <Button type="button" variant="outline" onClick={handleBack}>Back</Button>
              <Button type="submit" disabled={verifyCode.length < 6 || verifyMutation.isPending}>
                {verifyMutation.isPending ? 'Verifying…' : 'Verify & Enable'}
              </Button>
            </DialogFooter>
          </form>
        )}

        {step === 'backup-codes' && setupData && (
          <div className="space-y-4">
            <p role="status" className="flex items-center gap-2 rounded-md border status-green p-3">
              <CircleCheck className="h-4 w-4 shrink-0" />
              <span className="text-[12px] font-medium text-foreground">MFA enabled successfully</span>
            </p>

            <div>
              <h3 className="mb-1 text-[12px] font-medium text-foreground">Save your backup codes</h3>
              <p className="mb-3 text-[11px] leading-relaxed text-muted-foreground">
                Store these in a safe place. Each code can only be used once if you lose access
                to your authenticator app.
              </p>

              <ul
                aria-label="Backup codes"
                className="mb-3 grid grid-cols-2 gap-1.5 rounded-md border border-border bg-background p-3"
              >
                {setupData.backup_codes.map((code) => (
                  <li key={code} className="py-1 text-center font-mono text-[11px] tracking-widest text-foreground">
                    {code}
                  </li>
                ))}
              </ul>

              <div className="flex gap-2">
                <Button variant="outline" className="flex-1" onClick={handleCopyBackupCodes}>
                  {copied === 'backup-codes' ? 'Copied!' : 'Copy all'}
                </Button>
                <Button variant="outline" className="flex-1" onClick={() => downloadBackupCodes(setupData.backup_codes)}>
                  Download .txt
                </Button>
              </div>
            </div>

            <DialogFooter>
              <Button onClick={onClose}>Done</Button>
            </DialogFooter>
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}
