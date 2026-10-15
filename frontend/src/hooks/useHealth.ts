import { useQuery } from '@tanstack/react-query'
import { getHealth } from '../api/client'

/** Server mode (private/public, demo data, version). Public, cached for the session. */
export function useHealth() {
  return useQuery({
    queryKey: ['health'],
    queryFn: getHealth,
    staleTime: 5 * 60_000,
    retry: 3,
    retryDelay: (n) => Math.min(2000 * 2 ** n, 15_000),
  })
}
