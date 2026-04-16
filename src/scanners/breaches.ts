import type { ScanResult } from '../types.js'

interface BreachEntry {
  Name: string
  BreachDate: string
  DataClasses: string[]
}

export async function scanBreaches(domain: string): Promise<ScanResult> {
  const name = 'Breaches'

  try {
    const res = await fetch(
      `https://haveibeenpwned.com/api/v3/breaches?domain=${encodeURIComponent(domain)}`,
      {
        headers: {
          'User-Agent': 'UNPWNED-CLI',
        },
      }
    )

    if (res.status === 404 || res.status === 204) {
      return { name, score: 100, findings: [] }
    }

    if (!res.ok) {
      return { name, score: 100, findings: [], info: ['Breach check unavailable'] }
    }

    const breaches: BreachEntry[] = await res.json()

    if (!breaches || breaches.length === 0) {
      return { name, score: 100, findings: [] }
    }

    const findings = breaches.slice(0, 5).map((b) => ({
      severity: 'high' as const,
      title: `${b.Name} breach (${b.BreachDate})`,
      description: `Data exposed: ${b.DataClasses.slice(0, 4).join(', ')}`,
    }))

    const score = breaches.length >= 3 ? 0 : breaches.length >= 1 ? 40 : 100

    return {
      name,
      score,
      findings,
      info: [`${breaches.length} known breach${breaches.length !== 1 ? 'es' : ''}`],
    }
  } catch {
    return { name, score: 100, findings: [], info: ['Breach check unavailable'] }
  }
}
