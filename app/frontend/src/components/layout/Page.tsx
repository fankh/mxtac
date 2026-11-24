import type { ReactNode } from 'react'
import { TopBar } from './TopBar'
import { cn } from '@/lib/utils'

interface PageProps {
  title: string
  description?: string
  /** Buttons or filters shown on the right of the header bar. */
  actions?: ReactNode
  /** Extra classes for the body. Pass `p-0` for a full-bleed page. */
  className?: string
  children: ReactNode
}

/** Standard page frame: sticky header bar and a padded body with even spacing. */
export function Page({ title, description, actions, className, children }: PageProps) {
  return (
    <>
      <TopBar crumb={title} description={description} actions={actions} />
      <div className="pt-[46px]">
        <div className={cn('space-y-4 p-4', className)}>{children}</div>
      </div>
    </>
  )
}
