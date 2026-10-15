import type { Severity } from '../api/client'

export const SEV_COLOR: Record<Severity, string> = {
  CRITICAL: '#F2545B',
  HIGH: '#EE7A3B',
  MEDIUM: '#D9A514',
  LOW: '#7E9CC9',
}

export const SEV_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

export function riskColor(score: number): string {
  if (score >= 80) return SEV_COLOR.CRITICAL
  if (score >= 55) return SEV_COLOR.HIGH
  if (score >= 30) return SEV_COLOR.MEDIUM
  return SEV_COLOR.LOW
}

export function riskBand(score: number): string {
  if (score >= 80) return 'critical'
  if (score >= 55) return 'high'
  if (score >= 30) return 'medium'
  return 'low'
}
