import type { ReactNode } from 'react'
import { RefreshCw } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'

interface Props {
  title: string
  description?: string
  /** Controls shown on the right of the card header. */
  action?: ReactNode
  loading: boolean
  error: boolean
  onRetry: () => void
  /** Tailwind height class for the loading placeholder. */
  skeletonClass?: string
  className?: string
  children: ReactNode
}

/** Card with a title row and shared loading and error states for one request. */
export function CoverageCard({
  title, description, action, loading, error, onRetry, skeletonClass = 'h-[160px]', className, children,
}: Props) {
  return (
    <Card className={className}>
      <CardContent className="p-4">
        <div className="mb-3 flex items-start justify-between gap-3">
          <div className="min-w-0">
            <h3 className="text-[12px] font-semibold">{title}</h3>
            {description && <p className="mt-0.5 text-[11px] text-muted-foreground">{description}</p>}
          </div>
          {action}
        </div>
        {loading ? (
          <Skeleton className={cn('w-full', skeletonClass)} />
        ) : error ? (
          <div className="flex flex-col items-center gap-2 py-6 text-center" role="alert">
            <p className="text-[12px] text-destructive">Could not load {title.toLowerCase()}.</p>
            <Button variant="outline" size="sm" onClick={onRetry}>
              <RefreshCw className="mr-1 h-3 w-3" />
              Retry
            </Button>
          </div>
        ) : (
          children
        )}
      </CardContent>
    </Card>
  )
}
