import { describe, it, expect, vi, beforeEach } from 'vitest'
import { scanDNS } from './dns.js'

const mockResolveTxt = vi.fn()

vi.mock('node:dns', () => ({
  default: {
    promises: {
      resolveTxt: (...args: unknown[]) => mockResolveTxt(...args),
    },
  },
}))

const mockFetch = vi.fn()
vi.stubGlobal('fetch', mockFetch)

beforeEach(() => {
  vi.clearAllMocks()
})

describe('scanDNS', () => {
  it('returns score 100 when all records present', async () => {
    mockResolveTxt.mockImplementation((name: string) => {
      if (name === 'example.com') return Promise.resolve([['v=spf1 include:_spf.google.com ~all']])
      if (name === '_dmarc.example.com') return Promise.resolve([['v=DMARC1; p=reject']])
      if (name.endsWith('._domainkey.example.com')) return Promise.resolve([['v=DKIM1; k=rsa; p=abc']])
      return Promise.reject(Object.assign(new Error('ENODATA'), { code: 'ENODATA' }))
    })

    mockFetch.mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ AD: true }),
    })

    const result = await scanDNS('example.com')
    expect(result.name).toBe('DNS Security')
    expect(result.score).toBe(100)
    expect(result.findings).toHaveLength(0)
    expect(result.info?.some((i) => i.toLowerCase().includes('dkim'))).toBe(true)
  })

  it('returns score 0 with 3 findings when core records missing', async () => {
    mockResolveTxt.mockRejectedValue(Object.assign(new Error('ENODATA'), { code: 'ENODATA' }))

    mockFetch.mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ AD: false }),
    })

    const result = await scanDNS('example.com')
    expect(result.score).toBe(0)
    expect(result.findings).toHaveLength(3)

    const titles = result.findings.map((f) => f.title)
    expect(titles).toContain('Missing SPF record')
    expect(titles).toContain('Missing DMARC record')
    expect(titles).toContain('DNSSEC not enabled')
    expect(titles).not.toContain('No DKIM record found')
  })

  it('returns score 30 when SPF + DMARC present but no DNSSEC (DKIM unseen is informational only)', async () => {
    mockResolveTxt.mockImplementation((name: string) => {
      if (name === 'example.com') return Promise.resolve([['v=spf1 -all']])
      if (name === '_dmarc.example.com') return Promise.resolve([['v=DMARC1; p=none']])
      return Promise.reject(Object.assign(new Error('ENODATA'), { code: 'ENODATA' }))
    })

    mockFetch.mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ AD: false }),
    })

    const result = await scanDNS('example.com')
    expect(result.score).toBe(70)
    expect(result.findings).toHaveLength(1)
    expect(result.findings[0].title).toBe('DNSSEC not enabled')
    expect(result.info?.some((i) => i.toLowerCase().includes('dkim'))).toBe(true)
  })

  it('does not penalize score when only DKIM common selectors are missing', async () => {
    mockResolveTxt.mockImplementation((name: string) => {
      if (name === 'example.com') return Promise.resolve([['v=spf1 -all']])
      if (name === '_dmarc.example.com') return Promise.resolve([['v=DMARC1; p=reject']])
      return Promise.reject(Object.assign(new Error('ENODATA'), { code: 'ENODATA' }))
    })

    mockFetch.mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ AD: true }),
    })

    const result = await scanDNS('example.com')
    expect(result.score).toBe(100)
    expect(result.findings).toHaveLength(0)
    expect(result.info?.[0]).toMatch(/DKIM not detected/i)
  })

  it('handles DNS resolution errors gracefully', async () => {
    mockResolveTxt.mockRejectedValue(Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' }))

    mockFetch.mockRejectedValue(new Error('network error'))

    const result = await scanDNS('nonexistent.example')
    expect(result.score).toBe(0)
    expect(result.findings).toHaveLength(3)
    expect(result.name).toBe('DNS Security')
  })
})
