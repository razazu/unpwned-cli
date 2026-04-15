import { describe, it, expect } from 'vitest'
import { calculateScore, getGrade } from './scoring.js'
import type { ScanResult } from './types.js'

function makeScanResult(name: string, score: number): ScanResult {
  return { name, score, findings: [] }
}

function makeAllScanners(score: number): ScanResult[] {
  return [
    makeScanResult('Headers', score),
    makeScanResult('SSL/TLS', score),
    makeScanResult('DNS Security', score),
    makeScanResult('Cookies', score),
    makeScanResult('CORS', score),
    makeScanResult('Sensitive Files', score),
    makeScanResult('Tech Stack', score),
  ]
}

describe('calculateScore', () => {
  it('computes weighted average correctly', () => {
    const results: ScanResult[] = [
      makeScanResult('Headers', 50),
      makeScanResult('SSL/TLS', 100),
      makeScanResult('DNS Security', 0),
      makeScanResult('Cookies', 100),
      makeScanResult('CORS', 100),
      makeScanResult('Sensitive Files', 100),
      makeScanResult('Tech Stack', 100),
    ]
    // 50*0.25 + 100*0.20 + 0*0.20 + 100*0.10 + 100*0.10 + 100*0.10 + 100*0.05
    // = 12.5 + 20 + 0 + 10 + 10 + 10 + 5 = 67.5 -> 68
    expect(calculateScore(results)).toBe(68)
  })

  it('returns 0 when all scanners score 0', () => {
    expect(calculateScore(makeAllScanners(0))).toBe(0)
  })

  it('returns 100 when all scanners score 100', () => {
    expect(calculateScore(makeAllScanners(100))).toBe(100)
  })

  it('ignores unknown scanner names (weight 0)', () => {
    const results: ScanResult[] = [
      makeScanResult('Headers', 100),
      makeScanResult('Unknown Scanner', 100),
    ]
    // 100*0.25 + 100*0 = 25
    expect(calculateScore(results)).toBe(25)
  })

  it('returns 0 for empty results array', () => {
    expect(calculateScore([])).toBe(0)
  })
})

describe('getGrade', () => {
  it('returns A+ for score 100', () => {
    expect(getGrade(100)).toBe('A+')
  })

  it('returns A+ for score 95', () => {
    expect(getGrade(95)).toBe('A+')
  })

  it('returns A for score 94', () => {
    expect(getGrade(94)).toBe('A')
  })

  it('returns A for score 85', () => {
    expect(getGrade(85)).toBe('A')
  })

  it('returns B for score 84', () => {
    expect(getGrade(84)).toBe('B')
  })

  it('returns B for score 70', () => {
    expect(getGrade(70)).toBe('B')
  })

  it('returns C for score 69', () => {
    expect(getGrade(69)).toBe('C')
  })

  it('returns C for score 50', () => {
    expect(getGrade(50)).toBe('C')
  })

  it('returns D for score 49', () => {
    expect(getGrade(49)).toBe('D')
  })

  it('returns D for score 30', () => {
    expect(getGrade(30)).toBe('D')
  })

  it('returns F for score 29', () => {
    expect(getGrade(29)).toBe('F')
  })

  it('returns F for score 0', () => {
    expect(getGrade(0)).toBe('F')
  })
})
