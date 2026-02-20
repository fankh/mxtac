import { useEffect, useRef, useState } from 'react'
import { useDetectionStore } from '../stores/detectionStore'

/**
 * How long (ms) an alert ID stays in the "new" set.
 * Covers the 30 s visible period + 1 s buffer for the fade-out transition.
 */
const LIVE_DURATION_MS = 31_000

/**
 * Returns the set of detection IDs that arrived via WebSocket in the last 30 s.
 * Used by the UI to show a "Live" badge on newly-streamed alerts.
 */
export function useNewAlertIds(): ReadonlySet<string> {
  const liveAlerts = useDetectionStore((s) => s.liveAlerts)

  const [newIds, setNewIds] = useState<Set<string>>(new Set())

  /** IDs we have already scheduled a removal timer for — prevents double-tracking. */
  const seenRef = useRef<Set<string>>(new Set())
  const timersRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map())

  useEffect(() => {
    // liveAlerts is newest-first; collect IDs we haven't tracked yet.
    const toAdd: string[] = []
    for (const alert of liveAlerts) {
      if (seenRef.current.has(alert.id)) break // all subsequent are older → already tracked
      seenRef.current.add(alert.id)
      toAdd.push(alert.id)
    }

    if (toAdd.length === 0) return

    setNewIds((prev) => new Set([...prev, ...toAdd]))

    for (const id of toAdd) {
      const timer = setTimeout(() => {
        setNewIds((prev) => {
          const next = new Set(prev)
          next.delete(id)
          return next
        })
        timersRef.current.delete(id)
      }, LIVE_DURATION_MS)
      timersRef.current.set(id, timer)
    }
  }, [liveAlerts])

  // Clear all pending timers when the component using this hook unmounts.
  useEffect(() => {
    return () => {
      timersRef.current.forEach(clearTimeout)
    }
  }, [])

  return newIds
}
