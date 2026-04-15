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
  })

  it('returns score 0 with 4 findings when no records exist', async () => {
    mockResolveTxt.mockRejectedValue(Object.assign(new Error('ENODATA'), { code: 'ENODATA' }))

    mockFetch.mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ AD: false }),
    })

    const result = await scanDNS('example.com')
    expect(result.score).toBe(0)
    expect(result.findings).toHaveLength(4)

    const titles = result.findings.map((f) => f.title)
    expect(titles).toContain('Missing SPF record')
    expect(titles).toContain('Missing DMARC record')
    expect(titles).toContain('No DKIM record found')
    expect(titles).toContain('DNSSEC not enabled')
  })

  it('returns score 60 when SPF + DMARC present but no DKIM/DNSSEC', async () => {
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
    expect(result.score).toBe(60)
    expect(result.findings).toHaveLength(2)
    expect(result.findings[0].severity).toBe('medium')
    expect(result.findings[1].severity).toBe('medium')
  })

  it('handles DNS resolution errors gracefully', async () => {
    mockResolveTxt.mockRejectedValue(Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' }))

    mockFetch.mockRejectedValue(new Error('network error'))

    const result = await scanDNS('nonexistent.example')
    expect(result.score).toBe(0)
    expect(result.findings).toHaveLength(4)
    expect(result.name).toBe('DNS Security')
  })
})
