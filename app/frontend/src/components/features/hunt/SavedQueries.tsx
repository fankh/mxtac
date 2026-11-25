import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Bookmark, Pencil, RefreshCw, Trash2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from '@/components/ui/dialog'
import { EmptyState } from '@/components/ui/empty-state'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { Textarea } from '@/components/ui/textarea'
import { apiErrorMessage, savedQueriesApi } from '@/lib/api'
import { cn } from '@/lib/utils'
import { useUIStore } from '@/stores/uiStore'
import type { SavedQuery, SearchRequest } from '@/types/api'
import { timeRangeLabel } from './huntUtils'

const QUERY_KEY = ['hunt', 'saved-queries']

function describeSearch(query: string | null | undefined, filterCount: number, timeFrom: string | undefined): string {
  const parts: string[] = []
  if (query) parts.push(query)
  if (filterCount > 0) parts.push(`${filterCount} ${filterCount === 1 ? 'filter' : 'filters'}`)
  parts.push(timeRangeLabel(timeFrom ?? 'now-24h').toLowerCase())
  return parts.join(' · ')
}

// ── Save / edit dialog ───────────────────────────────────────────────────────

interface SaveDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** The search currently in the form; stored when creating, optional when editing. */
  search: SearchRequest
  /** Set to edit an existing saved query instead of creating one. */
  editing?: SavedQuery | null
  onSaved?: (saved: SavedQuery) => void
}

export function SaveQueryDialog({ open, onOpenChange, search, editing, onSaved }: SaveDialogProps) {
  const qc = useQueryClient()
  const addNotification = useUIStore((s) => s.addNotification)
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [replaceSearch, setReplaceSearch] = useState(false)

  // Reset the form each time the dialog opens or closes.
  useEffect(() => {
    setName(open && editing ? editing.name : '')
    setDescription(open && editing ? editing.description ?? '' : '')
    setReplaceSearch(false)
  }, [open, editing])

  const mutation = useMutation({
    mutationFn: () => {
      const stored = {
        query: search.query ?? '',
        filters: search.filters ?? [],
        time_from: search.time_from,
        time_to: search.time_to,
      }
      if (editing) {
        return savedQueriesApi.update(editing.id, {
          name: name.trim(),
          description: description.trim(),
          ...(replaceSearch ? stored : {}),
        })
      }
      return savedQueriesApi.create({
        name: name.trim(),
        description: description.trim() || undefined,
        ...stored,
        query: search.query,
      })
    },
    onSuccess: (saved) => {
      qc.invalidateQueries({ queryKey: QUERY_KEY })
      addNotification({ type: 'success', title: editing ? 'Saved query updated' : 'Query saved', message: saved.name })
      onSaved?.(saved)
      onOpenChange(false)
    },
    onError: (e: unknown) => {
      addNotification({
        type: 'error',
        title: editing ? 'Could not update the saved query' : 'Could not save the query',
        message: apiErrorMessage(e),
      })
    },
  })

  const currentSearch = describeSearch(search.query, search.filters?.length ?? 0, search.time_from)
  const canSubmit = name.trim().length > 0 && !mutation.isPending

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <form
          className="grid grid-cols-1 gap-3"
          onSubmit={(e) => { e.preventDefault(); if (canSubmit) mutation.mutate() }}
        >
          <DialogHeader>
            <DialogTitle>{editing ? 'Edit saved query' : 'Save query'}</DialogTitle>
            <DialogDescription>
              {editing ? 'Rename it, or replace the stored search with the one in the form.' : 'Only you can see your saved queries.'}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-1.5">
            <Label htmlFor="saved-query-name" className="text-[12px] font-medium">Name</Label>
            <Input
              id="saved-query-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              maxLength={255}
              placeholder="Lateral movement from one host"
              autoFocus
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="saved-query-description" className="text-[12px] font-medium">Description</Label>
            <Textarea
              id="saved-query-description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              maxLength={1000}
              placeholder="Optional"
              className="min-h-[60px]"
            />
          </div>
          {editing ? (
            <label className="flex items-start gap-2 text-[12px]">
              <input
                type="checkbox"
                checked={replaceSearch}
                onChange={(e) => setReplaceSearch(e.target.checked)}
                className="mt-0.5"
              />
              <span>
                Replace the stored search with the current one
                <span className="block text-[11px] text-muted-foreground">{currentSearch}</span>
              </span>
            </label>
          ) : (
            <p className="rounded-lg border border-border bg-muted/40 px-3 py-2 text-[11px] text-muted-foreground">
              {currentSearch}
            </p>
          )}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
            <Button type="submit" disabled={!canSubmit}>
              {mutation.isPending ? 'Saving…' : editing ? 'Save changes' : 'Save query'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

// ── List panel ───────────────────────────────────────────────────────────────

interface PanelProps {
  /** The search currently in the form (offered when editing a saved query). */
  search: SearchRequest
  /** ID of the saved query that was loaded last, to highlight it. */
  activeId: string | null
  onLoad: (saved: SavedQuery) => void
}

export function SavedQueriesPanel({ search, activeId, onLoad }: PanelProps) {
  const qc = useQueryClient()
  const addNotification = useUIStore((s) => s.addNotification)
  const [editing, setEditing] = useState<SavedQuery | null>(null)
  const [deleting, setDeleting] = useState<SavedQuery | null>(null)

  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: QUERY_KEY,
    queryFn: () => savedQueriesApi.list(),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => savedQueriesApi.delete(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: QUERY_KEY })
      setDeleting(null)
    },
    onError: (e: unknown) => {
      addNotification({
        type: 'error',
        title: 'Could not delete the saved query',
        message: apiErrorMessage(e),
      })
    },
  })

  const items = data?.items ?? []

  return (
    <Card>
      <CardContent className="p-4">
        <div className="mb-3 flex items-center justify-between">
          <h3 className="text-[12px] font-semibold">Saved queries</h3>
          {data && <span className="text-[11px] text-muted-foreground">{data.total}</span>}
        </div>

        {isLoading ? (
          <div className="space-y-2">
            {[0, 1, 2].map((i) => <Skeleton key={i} className="h-10 w-full" />)}
          </div>
        ) : isError ? (
          <div className="flex flex-col items-center gap-2 py-6 text-center">
            <p className="text-[12px] text-destructive">Could not load saved queries.</p>
            <Button variant="outline" size="sm" onClick={() => refetch()}>
              <RefreshCw className="mr-1 h-3 w-3" />
              Retry
            </Button>
          </div>
        ) : items.length === 0 ? (
          <EmptyState icon={Bookmark} title="No saved queries" description="Run a search, then save it to reuse it later." />
        ) : (
          <ul className="-mx-2 space-y-0.5">
            {items.map((sq) => (
              <li
                key={sq.id}
                className={cn(
                  'group flex items-center gap-1 rounded-md pr-1 transition-colors hover:bg-muted/60',
                  activeId === sq.id && 'bg-muted',
                )}
              >
                <Button
                  variant="ghost"
                  title={`Run ${sq.name}`}
                  onClick={() => onLoad(sq)}
                  className="h-auto min-w-0 flex-1 flex-col items-start gap-0.5 px-2 py-1.5 text-left font-normal hover:bg-transparent"
                >
                  <span className="w-full truncate text-[12px] font-medium text-foreground">{sq.name}</span>
                  <span className="w-full truncate text-[11px] text-muted-foreground">
                    {sq.description || describeSearch(sq.query, sq.filters.length, sq.time_from)}
                  </span>
                </Button>
                <Button
                  variant="ghost"
                  size="icon"
                  title={`Edit ${sq.name}`}
                  onClick={() => setEditing(sq)}
                  className="h-6 w-6 shrink-0 text-muted-foreground"
                >
                  <Pencil className="h-3 w-3" />
                </Button>
                <Button
                  variant="ghost"
                  size="icon"
                  title={`Delete ${sq.name}`}
                  onClick={() => setDeleting(sq)}
                  className="h-6 w-6 shrink-0 text-muted-foreground hover:text-destructive"
                >
                  <Trash2 className="h-3 w-3" />
                </Button>
              </li>
            ))}
          </ul>
        )}
      </CardContent>

      <SaveQueryDialog
        open={editing !== null}
        onOpenChange={(open) => { if (!open) setEditing(null) }}
        search={search}
        editing={editing}
      />

      <Dialog open={deleting !== null} onOpenChange={(open) => { if (!open) setDeleting(null) }}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>Delete saved query</DialogTitle>
            <DialogDescription>
              Delete "{deleting?.name}"? This cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleting(null)}>Cancel</Button>
            <Button
              variant="destructive"
              disabled={deleteMutation.isPending}
              onClick={() => { if (deleting) deleteMutation.mutate(deleting.id) }}
            >
              {deleteMutation.isPending ? 'Deleting…' : 'Delete'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  )
}
