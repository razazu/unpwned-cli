import { afterEach, describe, expect, it, vi } from 'vitest'
import { runHttpScanners } from './http-scan.js'
import { TargetError } from './target.js'

const SITE = 'https://site.test'

function fetchFailure(code: string): TypeError {
  return new TypeError('fetch failed', { cause: Object.assign(new Error(code), { code }) })
}

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

  it('stops with a clear error when the site refuses the connection', async () => {
    const fetchMock = vi.fn(async () => {
      throw fetchFailure('ECONNREFUSED')
    })
    vi.stubGlobal('fetch', fetchMock)

    const scan = runHttpScanners(SITE)

    await expect(scan).rejects.toBeInstanceOf(TargetError)
    await expect(scan).rejects.toThrow('Could not connect to https://site.test: the connection was refused.')
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('names the certificate problem when the certificate is rejected', async () => {
    const fetchMock = vi.fn(async () => {
      throw fetchFailure('CERT_HAS_EXPIRED')
    })
    vi.stubGlobal('fetch', fetchMock)

    await expect(runHttpScanners(SITE)).rejects.toThrow(
      'Could not connect to https://site.test: the certificate has expired.',
    )
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('does not retry a request that timed out', async () => {
    const fetchMock = vi.fn(async () => {
      throw new DOMException('The operation was aborted due to timeout', 'TimeoutError')
    })
    vi.stubGlobal('fetch', fetchMock)

    await expect(runHttpScanners(SITE)).rejects.toThrow(
      'Could not connect to https://site.test: no response within 10 seconds.',
    )
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('retries once after a transient failure and then scans the site', async () => {
    stubFetch((url, _init, call) => {
      if (call === 1) throw fetchFailure('ECONNRESET')
      return url === SITE ? healthyPage() : notFound()
    })

    const outcome = await runHttpScanners(SITE)

    expect(outcome.interference).toBeNull()
    expect(byName(outcome.results, 'Headers').score).toBe(100)
    expect(outcome.results.some((result) => result.skipped)).toBe(false)
  })

  it('stops when the site no longer responds after the sensitive file probes', async () => {
    let probesSeen = false
    stubFetch((url, init) => {
      if (url !== SITE) {
        probesSeen = true
        return notFound()
      }
      if (hasHeader(init, 'origin') || hasHeader(init, 'user-agent')) return healthyPage()
      if (probesSeen) throw fetchFailure('ECONNREFUSED')
      return healthyPage()
    })

    await expect(runHttpScanners(SITE)).rejects.toThrow(
      'https://site.test stopped responding during the scan: the connection was refused. A firewall may have blocked the scanner.',
    )
  })

  it('gives up after the retry fails too', async () => {
    const fetchMock = vi.fn(async () => {
      throw fetchFailure('ECONNRESET')
    })
    vi.stubGlobal('fetch', fetchMock)

    await expect(runHttpScanners(SITE)).rejects.toThrow(
      'Could not connect to https://site.test: the connection was reset.',
    )
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })
})
