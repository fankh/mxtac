import { Link } from 'react-router-dom'
import { ShieldCheck } from 'lucide-react'
import { formatDistanceToNowStrict } from 'date-fns'
import type { Detection } from '../../../types/api'
import { Card, CardContent } from '@/components/ui/card'
import { EmptyState } from '@/components/ui/empty-state'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { ScoreCircle } from '../../shared/SeverityBadge'
import { StatusPill } from '../../shared/StatusPill'

function timeAgo(iso: string): string {
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? '' : `${formatDistanceToNowStrict(d)} ago`
}

export function RecentDetectionsTable({ data }: { data: Detection[] }) {
  return (
    <Card>
      <CardContent className="p-4">
        <div className="mb-3 flex items-start justify-between gap-3">
          <div>
            <h3 className="text-[12px] font-semibold">Recent critical and high detections</h3>
            <p className="text-[11px] text-muted-foreground">Newest first</p>
          </div>
          <Link to="/detections" className="shrink-0 text-[11px] text-primary transition-colors hover:underline">
            View all
          </Link>
        </div>

        {data.length === 0 ? (
          <EmptyState icon={ShieldCheck} title="No critical or high detections" description="New alerts appear here as they arrive." />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                {['Score', 'Detection', 'Technique', 'Host', 'Status', 'Time'].map((h) => (
                  <TableHead key={h} className="h-8 text-[11px] font-medium text-muted-foreground">{h}</TableHead>
                ))}
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.map((row) => (
                <TableRow key={row.id}>
                  <TableCell className="py-2"><ScoreCircle score={row.score} severity={row.severity} /></TableCell>
                  <TableCell className="max-w-[260px] py-2 text-[12px]">
                    <div className="truncate">{row.name}</div>
                    <div className="truncate text-[11px] text-muted-foreground">{row.tactic}</div>
                  </TableCell>
                  <TableCell className="max-w-[200px] py-2 text-[12px]">
                    <div className="font-mono text-[11px]">{row.technique_id}</div>
                    <div className="truncate text-[11px] text-muted-foreground">{row.technique_name}</div>
                  </TableCell>
                  <TableCell className="whitespace-nowrap py-2 text-[12px]">{row.host}</TableCell>
                  <TableCell className="py-2"><StatusPill status={row.status} /></TableCell>
                  <TableCell className="whitespace-nowrap py-2 text-[11px] text-muted-foreground" title={new Date(row.time).toLocaleString()}>
                    {timeAgo(row.time)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  )
}
