import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { useUIStore } from '@/stores/uiStore'

interface ShortcutRow {
  keys: string[]
  description: string
}

interface ShortcutGroup {
  heading: string
  rows: ShortcutRow[]
}

const SHORTCUT_GROUPS: ShortcutGroup[] = [
  {
    heading: 'Navigation',
    rows: [
      { keys: ['g', 'd'], description: 'Go to Overview' },
      { keys: ['g', 'e'], description: 'Go to Detections' },
      { keys: ['g', 'r'], description: 'Go to Rules' },
      { keys: ['g', 'h'], description: 'Go to Hunt' },
      { keys: ['g', 'c'], description: 'Go to ATT&CK coverage' },
      { keys: ['g', 's'], description: 'Go to Sources' },
      { keys: ['g', 'i'], description: 'Go to Incidents' },
    ],
  },
  {
    heading: 'Actions',
    rows: [
      { keys: ['/'],   description: 'Focus search bar' },
      { keys: ['?'],   description: 'Show keyboard shortcuts' },
      { keys: ['Esc'], description: 'Close panel / modal' },
    ],
  },
]

function Key({ label }: { label: string }) {
  return (
    <kbd className="inline-flex h-[22px] min-w-[22px] items-center justify-center rounded border border-border bg-muted/50 px-1.5 font-mono text-[11px] font-semibold leading-none text-foreground/80">
      {label}
    </kbd>
  )
}

/**
 * Reference list of the keyboard shortcuts. Mount it to open it; Escape, an outside
 * click and the close button all clear `showShortcutsModal` in the UI store.
 */
export function KeyboardShortcutsModal() {
  const closeShortcutsModal = useUIStore((s) => s.closeShortcutsModal)

  return (
    <Dialog open onOpenChange={(next) => { if (!next) closeShortcutsModal() }}>
      <DialogContent className="max-w-sm gap-4 p-5">
        <DialogHeader>
          <DialogTitle>Keyboard Shortcuts</DialogTitle>
          <DialogDescription className="sr-only">
            Keys for moving between pages and for common actions.
          </DialogDescription>
        </DialogHeader>

        <div className="flex flex-col gap-5">
          {SHORTCUT_GROUPS.map((group) => (
            <section key={group.heading} aria-label={group.heading}>
              <h3 className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                {group.heading}
              </h3>
              <dl className="flex flex-col gap-1">
                {group.rows.map((row) => (
                  <div key={row.description} className="flex items-center justify-between py-1">
                    <dt className="text-xs text-foreground/80">{row.description}</dt>
                    <dd className="flex items-center gap-1">
                      {row.keys.map((k, idx) => (
                        <span key={idx} className="flex items-center gap-1">
                          {idx > 0 && (
                            <span className="text-[10px] text-muted-foreground">then</span>
                          )}
                          <Key label={k} />
                        </span>
                      ))}
                    </dd>
                  </div>
                ))}
              </dl>
            </section>
          ))}
        </div>
      </DialogContent>
    </Dialog>
  )
}
