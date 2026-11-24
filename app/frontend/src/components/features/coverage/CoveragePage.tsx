import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { Download, RefreshCw } from 'lucide-react'
import { Page } from '@/components/layout/Page'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { apiErrorMessage, coverageApi } from '@/lib/api'
import { useAuthStore } from '@/stores/authStore'
import { useUIStore } from '@/stores/uiStore'
import { downloadBlob } from '@/lib/download'
import { CoverageBySource } from './CoverageBySource'
import { CoverageMatrix } from './CoverageMatrix'
import { CoverageStats } from './CoverageStats'
import { CoverageTechniques } from './CoverageTechniques'
import { CoverageTrendChart } from './CoverageTrendChart'
import { TargetDialog } from './TargetDialog'
import { TARGET_EDIT_ROLES } from './coverageUtils'

/** ATT&CK coverage from enabled rules: headline numbers, trend, sources, matrix and gaps. */
export function CoveragePage() {
  const role = useAuthStore((s) => s.user?.role)
  const addNotification = useUIStore((s) => s.addNotification)
  const [targetOpen, setTargetOpen] = useState(false)
  const canEditTarget = role !== undefined && TARGET_EDIT_ROLES.includes(role)

  const summary = useQuery({ queryKey: ['coverage', 'summary'], queryFn: () => coverageApi.summary() })
  const gaps = useQuery({ queryKey: ['coverage', 'gaps'], queryFn: () => coverageApi.gaps() })
  const target = useQuery({ queryKey: ['coverage', 'target'], queryFn: () => coverageApi.target() })
  const layer = useQuery({ queryKey: ['coverage', 'navigator'], queryFn: () => coverageApi.navigator() })

  // Fetch the layer again on download so the file matches the rules as they are now.
  const download = useMutation({
    mutationFn: () => coverageApi.navigator(),
    onSuccess: (data) => {
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
      downloadBlob(blob, `mxtac-coverage-layer-${new Date().toISOString().slice(0, 10)}.json`)
    },
    onError: (e: unknown) => {
      addNotification({
        type: 'error',
        title: 'Could not download the Navigator layer',
        message: apiErrorMessage(e),
      })
    },
  })

  const headlineError = summary.isError || gaps.isError || target.isError

  return (
    <Page
      title="ATT&CK coverage"
      description="How much of ATT&CK the enabled rules cover"
      actions={
        <Button
          variant="outline"
          onClick={() => download.mutate()}
          disabled={download.isPending}
          title="Download a layer file for the MITRE ATT&CK Navigator"
        >
          <Download className="mr-1 h-3.5 w-3.5" />
          {download.isPending ? 'Preparing…' : 'Download Navigator layer'}
        </Button>
      }
    >
      {headlineError && (
        <Card role="alert">
          <CardContent className="flex flex-wrap items-center justify-between gap-3 p-4">
            <p className="text-[12px] text-destructive">Could not load some coverage numbers.</p>
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                if (summary.isError) summary.refetch()
                if (gaps.isError) gaps.refetch()
                if (target.isError) target.refetch()
              }}
            >
              <RefreshCw className="mr-1 h-3 w-3" />
              Retry
            </Button>
          </CardContent>
        </Card>
      )}

      <CoverageStats
        summary={summary.data}
        gaps={gaps.data}
        target={target.data}
        loading={summary.isLoading || gaps.isLoading || target.isLoading}
        canEditTarget={canEditTarget && target.data !== undefined}
        onEditTarget={() => setTargetOpen(true)}
      />

      <div className="grid gap-4 lg:grid-cols-3">
        <CoverageTrendChart targetPct={target.data?.target_pct} />
        <CoverageBySource />
      </div>

      <CoverageMatrix />
      <CoverageTechniques layer={layer} gaps={gaps} />

      <TargetDialog open={targetOpen} onOpenChange={setTargetOpen} target={target.data} />
    </Page>
  )
}
