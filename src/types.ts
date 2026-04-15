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
}

export interface ScanReport {
  target: string
  timestamp: string
  scanners: ScanResult[]
  overallScore: number
  grade: string
  duration: number
}
