import { describe, it, expect, vi, beforeEach } from 'vitest'
import { scanHeaders } from './headers.js'

function mockFetch(headers: Record<string, string>) {
  return vi.fn().mockResolvedValue({
    headers: new Headers(headers),
  })
}

beforeEach(() => {
  vi.restoreAllMocks()
})

describe('scanHeaders', () => {
  it('returns score 100 with no findings when all headers present', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({
        'content-security-policy': "default-src 'self'",
        'strict-transport-security': 'max-age=31536000',
        'x-frame-options': 'DENY',
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'strict-origin-when-cross-origin',
        'permissions-policy': 'camera=()',
      })
    )

    const result = await scanHeaders('https://example.com')

    expect(result.name).toBe('Headers')
    expect(result.score).toBe(100)
    expect(result.findings).toHaveLength(0)
  })

  it('returns score 0 with 6 findings when no headers present', async () => {
    vi.stubGlobal('fetch', mockFetch({}))

    const result = await scanHeaders('https://example.com')

    expect(result.name).toBe('Headers')
    expect(result.score).toBe(0)
    expect(result.findings).toHaveLength(6)

    const severities = result.findings.map((f) => f.severity)
    expect(severities.filter((s) => s === 'high')).toHaveLength(2)
    expect(severities.filter((s) => s === 'medium')).toHaveLength(2)
    expect(severities.filter((s) => s === 'low')).toHaveLength(2)
  })

  it('returns partial score with correct findings for some headers', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({
        'content-security-policy': "default-src 'self'",
        'strict-transport-security': 'max-age=31536000',
        'x-content-type-options': 'nosniff',
      })
    )

    const result = await scanHeaders('https://example.com')

    expect(result.name).toBe('Headers')
    expect(result.score).toBe(100 - 15 - 10 - 10)
    expect(result.findings).toHaveLength(3)

    const titles = result.findings.map((f) => f.title)
    expect(titles).toContain('Missing X-Frame-Options header')
    expect(titles).toContain('Missing Referrer-Policy header')
    expect(titles).toContain('Missing Permissions-Policy header')
    expect(titles).not.toContain('Missing Content-Security-Policy header')
  })

  it('returns score 0 with connection error finding on fetch failure', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockRejectedValue(new Error('Network error'))
    )

    const result = await scanHeaders('https://down.example.com')

    expect(result.name).toBe('Headers')
    expect(result.score).toBe(0)
    expect(result.findings).toHaveLength(1)
    expect(result.findings[0].severity).toBe('critical')
    expect(result.findings[0].title).toBe('Failed to connect')
  })
})
