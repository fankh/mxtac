import { useEffect, useState } from 'react'

/** How long (ms) the badge stays fully visible before starting to fade. */
const FADE_AT_MS = 30_000
/** Duration (ms) of the fade-out CSS transition. */
const FADE_DURATION_MS = 600

/**
 * A small "LIVE" tag that appears when an alert has just arrived via WebSocket.
 * After 30 s it fades out over 600 ms and then removes itself from the DOM.
 */
export function LiveBadge() {
  const [fading, setFading] = useState(false)
  const [hidden, setHidden] = useState(false)

  useEffect(() => {
    const fadeTimer = setTimeout(() => setFading(true), FADE_AT_MS)
    const hideTimer = setTimeout(() => setHidden(true), FADE_AT_MS + FADE_DURATION_MS)
    return () => {
      clearTimeout(fadeTimer)
      clearTimeout(hideTimer)
    }
  }, [])

  if (hidden) return null

  return (
    <span
      className={`inline-flex items-center px-1.5 py-px rounded text-[9px] font-bold tracking-wide bg-status-ok text-white transition-opacity duration-[600ms] ${
        fading ? 'opacity-0' : 'opacity-100'
      }`}
    >
      LIVE
    </span>
  )
}
