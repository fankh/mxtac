import { useCallback } from 'react'
import { useQuery } from '@tanstack/react-query'
import { attackApi } from '../lib/api'

/**
 * Lookup of MITRE ATT&CK technique names by ID, for the places that only have an ID
 * (rule tags, incident techniques, coverage lists).
 *
 * The table is bundled with the backend (GET /attack/techniques) and does not change while the
 * application runs, so it is fetched once and shared by every component. Until it has arrived,
 * and for an ID it does not contain, the lookup answers `undefined` and the ID is shown alone.
 */
export function useTechniqueNames(): (techniqueId: string) => string | undefined {
  const { data } = useQuery({
    queryKey: ['attack', 'techniques'],
    queryFn: attackApi.techniques,
    staleTime: Infinity,
    gcTime: Infinity,
    retry: 1,
  })
  const names = data?.techniques
  return useCallback((techniqueId: string) => names?.[techniqueId.trim().toUpperCase()], [names])
}
