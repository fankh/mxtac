import { useState, type FormEvent } from 'react'
import { ArrowRightLeft, MessageSquare, Paperclip, type LucideIcon } from 'lucide-react'
import type { IncidentNote, NoteType } from '@/types/api'
import { Button } from '@/components/ui/button'
import { EmptyState } from '@/components/ui/empty-state'
import { Textarea } from '@/components/ui/textarea'
import { OptionSelect } from '../detections/OptionSelect'
import { formatDateTime } from '../detections/utils'
import { NOTE_TYPE_LABELS } from './incidentUtils'

const NOTE_ICONS: Record<NoteType, LucideIcon> = {
  comment: MessageSquare,
  evidence: Paperclip,
  status_change: ArrowRightLeft,
}

/** Note types a person can add; status changes are written by the backend. */
type WritableNoteType = Exclude<NoteType, 'status_change'>

const NOTE_TYPE_OPTIONS: { value: WritableNoteType; label: string }[] = [
  { value: 'comment', label: NOTE_TYPE_LABELS.comment },
  { value: 'evidence', label: NOTE_TYPE_LABELS.evidence },
]

interface IncidentTimelineProps {
  notes: IncidentNote[]
  /** Hides the add-note form for read-only roles. */
  writable: boolean
  pending: boolean
  /** Resolves once the note is saved; the form clears only on success. */
  onAddNote: (content: string, noteType: WritableNoteType) => Promise<unknown>
}

/** Notes of an incident, oldest first, with a form to add one. */
export function IncidentTimeline({ notes, writable, pending, onAddNote }: IncidentTimelineProps) {
  const [content, setContent] = useState('')
  const [noteType, setNoteType] = useState<WritableNoteType>('comment')

  const ordered = [...notes].sort((a, b) => a.created_at.localeCompare(b.created_at))
  const trimmed = content.trim()

  function handleSubmit(event: FormEvent) {
    event.preventDefault()
    if (!trimmed || pending) return
    onAddNote(trimmed, noteType).then(
      () => setContent(''),
      () => undefined, // the caller reports the failure; keep the draft
    )
  }

  return (
    <div className="space-y-4">
      {ordered.length === 0 ? (
        <EmptyState icon={MessageSquare} title="No notes yet" description="Notes and status changes appear here." />
      ) : (
        <ol className="space-y-3">
          {ordered.map((note) => {
            const Icon = NOTE_ICONS[note.note_type] ?? MessageSquare
            return (
              <li key={note.id} className="flex gap-2.5">
                <span className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-muted text-muted-foreground">
                  <Icon className="h-3 w-3" />
                </span>
                <div className="min-w-0 flex-1">
                  <p className="text-[11px] text-muted-foreground">
                    <span className="font-medium text-foreground">{note.author}</span>
                    {' · '}
                    {NOTE_TYPE_LABELS[note.note_type] ?? note.note_type}
                    {' · '}
                    {formatDateTime(note.created_at)}
                  </p>
                  <p className="whitespace-pre-wrap break-words text-[12px] text-foreground">{note.content}</p>
                </div>
              </li>
            )
          })}
        </ol>
      )}

      {writable && (
        <form onSubmit={handleSubmit} className="space-y-2 border-t border-border pt-3">
          <Textarea
            aria-label="New note"
            rows={3}
            maxLength={5000}
            value={content}
            onChange={(e) => setContent(e.target.value)}
            placeholder="Add a note or a piece of evidence"
          />
          <div className="flex items-center justify-between gap-2">
            <OptionSelect label="Note type" value={noteType} options={NOTE_TYPE_OPTIONS} onChange={setNoteType} />
            <Button type="submit" disabled={!trimmed || pending}>
              {pending ? 'Adding…' : 'Add note'}
            </Button>
          </div>
        </form>
      )}
    </div>
  )
}
