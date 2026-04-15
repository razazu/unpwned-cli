import type { ScanResult } from './types.js'

const WEIGHTS: Record<string, number> = {
  'Headers': 0.25,
  'SSL/TLS': 0.20,
  'DNS Security': 0.20,
  'Cookies': 0.10,
  'CORS': 0.10,
  'Sensitive Files': 0.10,
  'Tech Stack': 0.05,
}

export function calculateScore(results: ScanResult[]): number {
  let total = 0
  for (const result of results) {
    const weight = WEIGHTS[result.name] ?? 0
    total += result.score * weight
  }
  return Math.round(total)
}

export function getGrade(score: number): string {
  if (score >= 95) return 'A+'
  if (score >= 85) return 'A'
  if (score >= 70) return 'B'
  if (score >= 50) return 'C'
  if (score >= 30) return 'D'
  return 'F'
}
