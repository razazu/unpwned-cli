import { afterEach, describe, expect, it, vi } from 'vitest'
import { runHttpScanners } from './http-scan.js'

const SITE = 'https://site.test'

const SECURE_HEADERS = {
  'content-security-policy': "default-src 'self'",
  'strict-transport-security': 'max-age=63072000',
  'x-frame-options': 'DENY',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'permissions-policy': 'camera=()',
  'x-powered-by': 'Express',
}

type Responder = (url: string, init: RequestInit | undefined, call: number) => Response

function stubFetch(responder: Responder) {
  let call = 0
  const mock = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    call += 1
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    return responder(url, init, call)
  })
  vi.stubGlobal('fetch', mock)
  return mock
}

function healthyPage(): Response {
  return new Response('<html><body>ok</body></html>', { status: 200, headers: SECURE_HEADERS })
}

function challengePage(): Response {
  return new Response('<title>Just a moment...</title>', { status: 403, headers: { 'cf-mitigated': 'challenge' } })
}

function notFound(): Response {
  return new Response('not found', { status: 404 })
}

function hasHeader(init: RequestInit | undefined, name: string): boolean {
  return new Headers(init?.headers).has(name)
}

function byName(results: { name: string }[], name: string) {
  const match = results.find((result) => result.name === name)
  if (!match) throw new Error(`missing result for ${name}`)
  return match as { name: string; score: number; skipped?: boolean; info?: string[]; findings: { title: string }[] }
}

describe('runHttpScanners', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('scans a reachable site and reports no interference', async () => {
    stubFetch((url) => (url === SITE ? healthyPage() : notFound()))

    const outcome = await runHttpScanners(SITE)

    expect(outcome.interference).toBeNull()
    expect(outcome.results.map((result) => result.name)).toEqual([
      'Headers',
      'Cookies',
      'CORS',
      'Sensitive Files',
      'Tech Stack',
    ])
    expect(outcome.results.some((result) => result.skipped)).toBe(false)
    expect(byName(outcome.results, 'Headers').score).toBe(100)
    expect(byName(outcome.results, 'CORS').score).toBe(100)
    expect(byName(outcome.results, 'Tech Stack').info).toContain('Express')
  })

  it('skips every scanner and sends no further requests when the site blocks the first request', async () => {
    const fetchMock = stubFetch(() => challengePage())

    const outcome = await runHttpScanners(SITE)

    expect(outcome.interference).toEqual({ status: 403, provider: 'Cloudflare', reason: 'challenge' })
    expect(outcome.results).toHaveLength(5)
    expect(outcome.results.every((result) => result.skipped)).toBe(true)
    expect(outcome.results.every((result) => result.findings.length === 0)).toBe(true)
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('skips only the scanner whose own request was blocked', async () => {
    stubFetch((url, init) => {
      if (url !== SITE) return notFound()
      return hasHeader(init, 'origin') ? challengePage() : healthyPage()
    })

    const outcome = await runHttpScanners(SITE)

    expect(outcome.interference?.provider).toBe('Cloudflare')
    expect(byName(outcome.results, 'CORS').skipped).toBe(true)
    expect(byName(outcome.results, 'Headers').skipped).toBeUndefined()
    expect(byName(outcome.results, 'Headers').score).toBe(100)
    expect(byName(outcome.results, 'Tech Stack').skipped).toBeUndefined()
  })

  it('discards the sensitive files result when the site starts blocking during the probes', async () => {
    let probesSeen = false
    stubFetch((url, init) => {
      if (url !== SITE) {
        probesSeen = true
        return notFound()
      }
      if (hasHeader(init, 'origin') || hasHeader(init, 'user-agent')) return healthyPage()
      return probesSeen ? challengePage() : healthyPage()
    })

    const outcome = await runHttpScanners(SITE)

    expect(outcome.interference?.reason).toBe('challenge')
    expect(byName(outcome.results, 'Sensitive Files').skipped).toBe(true)
    expect(byName(outcome.results, 'Headers').score).toBe(100)
    expect(byName(outcome.results, 'CORS').skipped).toBeUndefined()
  })

  it('reports connection failures as findings, not as interference', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new TypeError('fetch failed')
      }),
    )

    const outcome = await runHttpScanners(SITE)

    expect(outcome.interference).toBeNull()
    expect(outcome.results.some((result) => result.skipped)).toBe(false)
    expect(byName(outcome.results, 'Headers').findings[0].title).toBe('Failed to connect')
    expect(byName(outcome.results, 'Cookies').findings[0].title).toBe('Failed to connect')
    expect(byName(outcome.results, 'CORS').findings[0].title).toBe('Failed to connect')
  })
})
