import { afterEach, describe, expect, it, vi } from 'vitest'
import { describeInterference, detectInterference, probeInterference } from './interference.js'

function headers(init: Record<string, string> = {}): Headers {
  return new Headers(init)
}

describe('detectInterference', () => {
  it('returns null for a normal page', () => {
    expect(detectInterference(200, headers({ server: 'cloudflare' }), '<html>Welcome</html>')).toBeNull()
  })

  it('returns null for a plain 403 with no block markers', () => {
    expect(detectInterference(403, headers(), '<html>Sign in to continue</html>')).toBeNull()
  })

  it('returns null for a 503 maintenance page', () => {
    expect(detectInterference(503, headers(), '<html>Back soon, we are deploying.</html>')).toBeNull()
  })

  it('detects a Cloudflare challenge from the cf-mitigated header', () => {
    expect(detectInterference(403, headers({ 'cf-mitigated': 'challenge' }), '')).toEqual({
      status: 403,
      provider: 'Cloudflare',
      reason: 'challenge',
    })
  })

  it('detects a Vercel challenge from the x-vercel-mitigated header', () => {
    expect(detectInterference(403, headers({ 'x-vercel-mitigated': 'challenge' }), '')).toEqual({
      status: 403,
      provider: 'Vercel',
      reason: 'challenge',
    })
  })

  it('detects a Vercel deny as a block', () => {
    expect(detectInterference(403, headers({ 'x-vercel-mitigated': 'deny' }), '')?.reason).toBe('blocked')
  })

  it('detects a Cloudflare block page from its body', () => {
    const body = '<title>Attention Required! | Cloudflare</title><h1>Sorry, you have been blocked</h1>'
    expect(detectInterference(403, headers({ server: 'cloudflare' }), body)).toEqual({
      status: 403,
      provider: 'Cloudflare',
      reason: 'blocked',
    })
  })

  it('detects a Cloudflare interstitial from its body', () => {
    const body = '<title>Just a moment...</title><script src="/cdn-cgi/challenge-platform/h/b/orchestrate"></script>'
    expect(detectInterference(503, headers(), body)?.reason).toBe('challenge')
  })

  it('detects an Akamai block page', () => {
    const body = '<h1>Access Denied</h1>You do not have permission. Reference #18.2f1d1002.1700000000.1a2b3c'
    expect(detectInterference(403, headers(), body)?.provider).toBe('Akamai')
  })

  it('detects an application-level block message without a known provider', () => {
    const body = 'Requests from your network are temporarily blocked by our automated abuse-prevention system.'
    expect(detectInterference(403, headers({ server: 'cloudflare' }), body)).toEqual({
      status: 403,
      provider: null,
      reason: 'blocked',
    })
  })

  it('treats any 429 as rate limiting', () => {
    expect(detectInterference(429, headers(), '')).toEqual({
      status: 429,
      provider: null,
      reason: 'rate-limited',
    })
  })

  it('ignores block wording on a successful response', () => {
    expect(detectInterference(200, headers(), 'How to fix an Access Denied error')).toBeNull()
  })
})

describe('probeInterference', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('reports a challenge response', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('checking your browser', { status: 403, headers: { 'cf-mitigated': 'challenge' } })),
    )

    expect(await probeInterference('https://example.com')).toEqual({
      status: 403,
      provider: 'Cloudflare',
      reason: 'challenge',
    })
  })

  it('returns null when the page loads normally', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('<html>ok</html>', { status: 200 })))

    expect(await probeInterference('https://example.com')).toBeNull()
  })

  it('returns null when the request fails', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new TypeError('fetch failed')
      }),
    )

    expect(await probeInterference('https://example.com')).toBeNull()
  })
})

describe('describeInterference', () => {
  it('names the provider and the kind of response', () => {
    expect(describeInterference({ status: 403, provider: 'Cloudflare', reason: 'challenge' })).toBe(
      'HTTP 403, Cloudflare challenge page',
    )
    expect(describeInterference({ status: 429, provider: null, reason: 'rate-limited' })).toBe('HTTP 429, rate limit')
    expect(describeInterference({ status: 403, provider: null, reason: 'blocked' })).toBe('HTTP 403, block page')
  })
})
