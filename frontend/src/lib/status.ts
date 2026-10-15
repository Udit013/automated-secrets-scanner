import type { CredentialStatus } from '../api/client'

export const STATUS_LABEL: Record<CredentialStatus, string> = {
  open: 'open',
  rotated: 'rotated',
  false_positive: 'false positive',
  accepted_risk: 'accepted risk',
}
