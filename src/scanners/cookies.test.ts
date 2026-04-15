import { describe, it, expect, vi, beforeEach } from 'vitest'
import { scanCookies } from './cookies.js'

function mockFetch(setCookies: string[]) {
  const headers = new Headers()
  for (const cookie of setCookies) {
    headers.append('set-cookie', cookie)
  }
  return vi.fn().mockResolvedValue({ headers })
}

beforeEach(() => {
  vi.restoreAllMocks()
})

describe('scanCookies', () => {
  it('returns score 100 with no findings when no cookies set', async () => {
    vi.stubGlobal('fetch', mockFetch([]))

    const result = await scanCookies('https://example.com')

    expect(result.name).toBe('Cookies')
    expect(result.score).toBe(100)
    expect(result.findings).toHaveLength(0)
  })

  it('returns score 100 when cookie has all flags', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch(['sid=abc123; Secure; HttpOnly; SameSite=Strict'])
    )

    const result = await scanCookies('https://example.com')

    expect(result.name).toBe('Cookies')
    expect(result.score).toBe(100)
    expect(result.findings).toHaveLength(0)
  })

  it('reports high finding when cookie missing Secure flag on HTTPS', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch(['sid=abc123; HttpOnly; SameSite=Lax'])
    )

    const result = await scanCookies('https://example.com')

    expect(result.name).toBe('Cookies')
    expect(result.findings).toHaveLength(1)
    expect(result.findings[0].severity).toBe('high')
    expect(result.findings[0].title).toContain('Secure')
    expect(result.score).toBe(67)
  })

  it('reports 3 findings when cookie missing all flags', async () => {
    vi.stubGlobal('fetch', mockFetch(['sid=abc123']))

    const result = await scanCookies('https://example.com')

    expect(result.name).toBe('Cookies')
    expect(result.findings).toHaveLength(3)

    const severities = result.findings.map((f) => f.severity)
    expect(severities).toContain('high')
    expect(severities).toContain('medium')
    expect(severities).toContain('low')
    expect(result.score).toBe(0)
  })

  it('calculates partial score with multiple cookies and mixed flags', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch([
        'sid=abc; Secure; HttpOnly; SameSite=Strict',
        'prefs=dark',
      ])
    )

    const result = await scanCookies('https://example.com')

    expect(result.name).toBe('Cookies')
    expect(result.findings).toHaveLength(3)
    expect(result.score).toBe(50)
  })

  it('returns score 0 with connection error finding on fetch failure', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockRejectedValue(new Error('Network error'))
    )

    const result = await scanCookies('https://down.example.com')

    expect(result.name).toBe('Cookies')
    expect(result.score).toBe(0)
    expect(result.findings).toHaveLength(1)
    expect(result.findings[0].severity).toBe('critical')
    expect(result.findings[0].title).toBe('Failed to connect')
  })
})
