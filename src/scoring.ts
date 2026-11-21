import type { ScanResult } from './types.js'

const WEIGHTS: Record<string, number> = {
  'Headers': 0.25,
  'SSL/TLS': 0.20,
  'DNS Security': 0.15,
  'Cookies': 0.10,
  'CORS': 0.10,
  'Sensitive Files': 0.10,
  'Breaches': 0.10,
  'Tech Stack': 0,
}

export function calculateScore(results: ScanResult[]): number {
  const scored = results.filter((result) => !result.skipped)

  let total = 0
  let weightSum = 0
  for (const result of scored) {
    const weight = WEIGHTS[result.name] ?? 0
    total += result.score * weight
    weightSum += weight
  }

  if (scored.length === results.length) return Math.round(total)
  return weightSum > 0 ? Math.round(total / weightSum) : 0
}

export function getGrade(score: number): string {
  if (score >= 95) return 'A+'
  if (score >= 85) return 'A'
  if (score >= 70) return 'B'
  if (score >= 50) return 'C'
  if (score >= 30) return 'D'
  return 'F'
}
