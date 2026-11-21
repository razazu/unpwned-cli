export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export interface Finding {
  severity: Severity
  title: string
  description: string
}

export interface ScanResult {
  name: string
  score: number
  findings: Finding[]
  info?: string[]
  skipped?: boolean
  skipReason?: 'blocked' | 'not-applicable'
}

export interface ScanInterference {
  status: number
  provider: string | null
  reason: 'challenge' | 'blocked' | 'rate-limited'
}

export interface ScanReport {
  target: string
  timestamp: string
  scanners: ScanResult[]
  overallScore: number
  grade: string
  duration: number
  interference?: ScanInterference
}
