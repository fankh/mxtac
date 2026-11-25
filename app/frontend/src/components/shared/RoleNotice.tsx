import { Lock } from 'lucide-react'
import { Card } from '@/components/ui/card'
import { EmptyState } from '@/components/ui/empty-state'

/** Shown in place of a page the signed-in role may not open, instead of a failed request. */
export function RoleNotice({ title, description }: { title: string; description: string }) {
  return (
    <Card>
      <EmptyState icon={Lock} title={title} description={description} />
    </Card>
  )
}
