import type { ScanInterference } from './types.js'

const BLOCK_STATUSES = new Set([403, 406, 429, 503])

const BODY_LIMIT = 20000

interface BodyMarker {
  provider: string | null
  reason: ScanInterference['reason']
  pattern: RegExp
}

const BODY_MARKERS: BodyMarker[] = [
  { provider: 'Cloudflare', reason: 'challenge', pattern: /challenge-platform|Just a moment\.\.\./i },
  {
    provider: 'Cloudflare',
    reason: 'blocked',
    pattern: /Attention Required! \| Cloudflare|Sorry, you have been blocked|cf-error-details/i,
  },
  { provider: 'Akamai', reason: 'blocked', pattern: /Access Denied[\s\S]{0,400}Reference(?:&#32;&#35;| #)/i },
  { provider: 'Imperva', reason: 'blocked', pattern: /_Incapsula_Resource|Incapsula incident ID/i },
  {
    provider: 'AWS CloudFront',
    reason: 'blocked',
    pattern: /The request could not be satisfied[\s\S]{0,600}Request blocked/i,
  },
  {
    provider: null,
    reason: 'challenge',
    pattern: /verify (?:that )?you are (?:a )?human|are you a robot|complete the captcha|unusual traffic/i,
  },
  {
    provider: null,
    reason: 'rate-limited',
    pattern: /too many requests|rate limit(?:ed)? exceeded/i,
  },
  {
    provider: null,
    reason: 'blocked',
    pattern: /temporarily blocked|access denied|request blocked|has been blocked|have been blocked/i,
  },
]

export function detectInterference(status: number, headers: Headers, body: string): ScanInterference | null {
  if (headers.get('cf-mitigated')?.toLowerCase() === 'challenge') {
    return { status, provider: 'Cloudflare', reason: 'challenge' }
  }

  const vercelMitigation = headers.get('x-vercel-mitigated')?.toLowerCase()
  if (vercelMitigation) {
    return { status, provider: 'Vercel', reason: vercelMitigation === 'challenge' ? 'challenge' : 'blocked' }
  }

  if (headers.has('x-sucuri-block')) {
    return { status, provider: 'Sucuri', reason: 'blocked' }
  }

  const awsWafAction = headers.get('x-amzn-waf-action')?.toLowerCase()
  if (awsWafAction) {
    return { status, provider: 'AWS WAF', reason: awsWafAction === 'block' ? 'blocked' : 'challenge' }
  }

  if (!BLOCK_STATUSES.has(status)) return null

  if (headers.has('x-datadome')) {
    return { status, provider: 'DataDome', reason: 'blocked' }
  }

  const sample = body.slice(0, BODY_LIMIT)
  for (const marker of BODY_MARKERS) {
    if (marker.pattern.test(sample)) {
      return { status, provider: marker.provider, reason: marker.reason }
    }
  }

  if (status === 429) {
    return { status, provider: null, reason: 'rate-limited' }
  }

  return null
}

export async function probeInterference(url: string): Promise<ScanInterference | null> {
  try {
    const response = await fetch(url, {
      redirect: 'follow',
      signal: AbortSignal.timeout(10000),
    })
    const body = await response.text()
    return detectInterference(response.status, response.headers, body)
  } catch {
    return null
  }
}

export function describeInterference(interference: ScanInterference): string {
  const what =
    interference.reason === 'challenge'
      ? 'challenge page'
      : interference.reason === 'rate-limited'
        ? 'rate limit'
        : 'block page'
  const who = interference.provider ? `${interference.provider} ` : ''
  return `HTTP ${interference.status}, ${who}${what}`
}
