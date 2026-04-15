import { describe, it, expect, vi, beforeEach } from 'vitest'
import { scanCORS } from './cors.js'

function mockFetch(headers: Record<string, string>) {
  return vi.fn().mockResolvedValue({
    headers: new Headers(headers),
  })
}

beforeEach(() => {
  vi.restoreAllMocks()
})

describe('scanCORS', () => {
  it('returns score 100 when no CORS headers present', async () => {
    vi.stubGlobal('fetch', mockFetch({}))

    const result = await scanCORS('https://example.com')

    expect(result.name).toBe('CORS')
    expect(result.score).toBe(100)
    expect(result.findings).toHaveLength(0)
  })

  it('returns medium finding for wildcard origin', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({ 'access-control-allow-origin': '*' })
    )

    const result = await scanCORS('https://example.com')

    expect(result.name).toBe('CORS')
    expect(result.score).toBe(70)
    expect(result.findings).toHaveLength(1)
    expect(result.findings[0].severity).toBe('medium')
    expect(result.findings[0].title).toBe(
      'Wildcard CORS policy allows any origin'
    )
  })

  it('returns high finding for origin reflection', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({ 'access-control-allow-origin': 'https://evil.com' })
    )

    const result = await scanCORS('https://example.com')

    expect(result.name).toBe('CORS')
    expect(result.score).toBe(50)
    expect(result.findings).toHaveLength(1)
    expect(result.findings[0].severity).toBe('high')
    expect(result.findings[0].title).toBe('CORS reflects arbitrary origins')
  })

  it('returns critical finding for origin reflection with credentials', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({
        'access-control-allow-origin': 'https://evil.com',
        'access-control-allow-credentials': 'true',
      })
    )

    const result = await scanCORS('https://example.com')

    expect(result.name).toBe('CORS')
    expect(result.score).toBe(30)
    expect(result.findings).toHaveLength(1)
    expect(result.findings[0].severity).toBe('critical')
    expect(result.findings[0].title).toBe(
      'CORS allows credentials from any origin'
    )
  })

  it('returns score 0 with connection error on fetch failure', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockRejectedValue(new Error('Network error'))
    )

    const result = await scanCORS('https://down.example.com')

    expect(result.name).toBe('CORS')
    expect(result.score).toBe(0)
    expect(result.findings).toHaveLength(1)
    expect(result.findings[0].severity).toBe('critical')
    expect(result.findings[0].title).toBe('Failed to connect')
  })
})
