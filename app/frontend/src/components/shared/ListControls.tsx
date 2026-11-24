import type { ReactNode } from 'react'
import { ChevronLeft, ChevronRight, RefreshCw, Search, TriangleAlert, X } from 'lucide-react'
import type { Pagination } from '@/types/api'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { cn } from '@/lib/utils'

interface SearchInputProps {
  value: string
  onChange: (value: string) => void
  placeholder: string
  /** Accessible name; defaults to the placeholder. */
  label?: string
  /** Show the magnifier icon (off for secondary text filters). */
  icon?: boolean
  className?: string
}

/** Text filter with a clear button; Escape also clears it. */
export function SearchInput({ value, onChange, placeholder, label, icon = true, className }: SearchInputProps) {
  const name = label ?? placeholder
  return (
    <div className={cn('relative w-full sm:w-56', className)}>
      {icon && (
        <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
      )}
      <Input
        type="text"
        aria-label={name}
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Escape' && value) {
            e.stopPropagation()
            onChange('')
          }
        }}
        className={cn('h-8 pr-8', icon && 'pl-8')}
      />
      {value && (
        <Button
          type="button"
          variant="ghost"
          size="icon"
          title={`Clear ${name.toLowerCase()}`}
          onClick={() => onChange('')}
          className="absolute right-1 top-1/2 h-6 w-6 -translate-y-1/2 text-muted-foreground"
        >
          <X className="h-3.5 w-3.5" />
        </Button>
      )}
    </div>
  )
}

interface FilterChipProps {
  label: string
  active: boolean
  onClick: () => void
}

/** Toggle button used for multi-value filters. */
export function FilterChip({ label, active, onClick }: FilterChipProps) {
  return (
    <Button
      type="button"
      size="sm"
      variant={active ? 'default' : 'outline'}
      aria-pressed={active}
      onClick={onClick}
    >
      {label}
    </Button>
  )
}

export function FilterGroup({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div role="group" aria-label={label} className="flex flex-wrap items-center gap-1">
      <span className="mr-1 text-[11px] text-muted-foreground">{label}</span>
      {children}
    </div>
  )
}

interface ErrorCardProps {
  title: string
  message: string
  onRetry: () => void
}

/** Inline request-failure card with a retry action. */
export function ErrorCard({ title, message, onRetry }: ErrorCardProps) {
  return (
    <Card role="alert">
      <CardContent className="flex flex-col items-center gap-2 p-4 py-8 text-center">
        <TriangleAlert className="h-6 w-6 text-destructive" />
        <p className="text-[12px] font-semibold text-foreground">{title}</p>
        <p className="text-[11px] text-muted-foreground">{message}</p>
        <Button variant="outline" onClick={onRetry} className="mt-1 gap-1.5">
          <RefreshCw className="h-3.5 w-3.5" />
          Retry
        </Button>
      </CardContent>
    </Card>
  )
}

interface PagerProps {
  pagination: Pagination
  onPageChange: (page: number) => void
  /** Extra controls shown before the page buttons (for example a page-size select). */
  children?: ReactNode
}

export function Pager({ pagination, onPageChange, children }: PagerProps) {
  const { page, page_size, total, total_pages } = pagination
  const first = total === 0 ? 0 : (page - 1) * page_size + 1
  const last = Math.min(page * page_size, total)
  return (
    <div className="flex flex-wrap items-center justify-between gap-2">
      <span className="text-[11px] text-muted-foreground">
        {first.toLocaleString('en-US')}–{last.toLocaleString('en-US')} of {total.toLocaleString('en-US')}
      </span>
      <div className="flex items-center gap-2">
        {children}
        <Button
          variant="outline"
          size="icon"
          title="Previous page"
          disabled={page <= 1}
          onClick={() => onPageChange(page - 1)}
        >
          <ChevronLeft className="h-3.5 w-3.5" />
        </Button>
        <span className="text-[11px] text-muted-foreground">
          Page {page} of {total_pages}
        </span>
        <Button
          variant="outline"
          size="icon"
          title="Next page"
          disabled={page >= total_pages}
          onClick={() => onPageChange(page + 1)}
        >
          <ChevronRight className="h-3.5 w-3.5" />
        </Button>
      </div>
    </div>
  )
}
