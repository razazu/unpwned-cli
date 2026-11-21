import dns from 'node:dns'
import { isIP } from 'node:net'
import { platformSuffix } from '../platforms.js'
import type { Finding, ScanResult } from '../types.js'

const DKIM_SELECTORS = ['default', 'google', 'selector1', 'selector2', 'k1']

function domainCandidates(domain: string): string[] {
  const labels = domain.split('.').filter(Boolean)
  const candidates: string[] = []
  for (let start = 0; start <= labels.length - 2; start++) {
    candidates.push(labels.slice(start).join('.'))
  }
  return candidates
}

async function hasTxtRecord(name: string, marker: string): Promise<boolean> {
  try {
    const records = await dns.promises.resolveTxt(name)
    return records.some((parts) => parts.join('').includes(marker))
  } catch {
    return false
  }
}

async function anyOf(checks: Promise<boolean>[]): Promise<boolean> {
  return (await Promise.all(checks)).some(Boolean)
}

function checkSPF(candidates: string[]): Promise<boolean> {
  return anyOf(candidates.map((domain) => hasTxtRecord(domain, 'v=spf1')))
}

function checkDMARC(candidates: string[]): Promise<boolean> {
  return anyOf(candidates.map((domain) => hasTxtRecord('_dmarc.' + domain, 'v=DMARC1')))
}

async function checkDKIM(candidates: string[]): Promise<boolean> {
  for (const domain of candidates) {
    for (const selector of DKIM_SELECTORS) {
      try {
        const records = await dns.promises.resolveTxt(selector + '._domainkey.' + domain)
        if (records.length > 0) return true
      } catch {
        continue
      }
    }
  }
  return false
}

async function checkDNSSEC(domain: string): Promise<boolean> {
  try {
    const res = await fetch(
      `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A&do=1`,
      { signal: AbortSignal.timeout(5000) },
    )
    if (!res.ok) return false
    const data = (await res.json()) as { AD?: boolean }
    return data.AD === true
  } catch {
    return false
  }
}

function notApplicable(reason: string): ScanResult {
  return {
    name: 'DNS Security',
    score: 0,
    findings: [],
    info: [reason],
    skipped: true,
    skipReason: 'not-applicable',
  }
}

export async function scanDNS(domain: string): Promise<ScanResult> {
  if (isIP(domain)) {
    return notApplicable('DNS checks do not apply to an IP address.')
  }

  const platform = platformSuffix(domain)
  if (platform) {
    return notApplicable(`DNS for *.${platform} is managed by the hosting platform.`)
  }

  const candidates = domainCandidates(domain)
  if (candidates.length === 0) {
    return notApplicable('DNS checks do not apply to a single-label host name.')
  }

  const findings: Finding[] = []
  const info: string[] = []
  let score = 100

  const [hasSPF, hasDMARC, hasDKIM, hasDNSSEC] = await Promise.all([
    checkSPF(candidates),
    checkDMARC(candidates),
    checkDKIM(candidates),
    checkDNSSEC(domain),
  ])

  if (!hasSPF) {
    score -= 35
    findings.push({
      severity: 'high',
      title: 'Missing SPF record',
      description:
        'No SPF (Sender Policy Framework) record found. Attackers can spoof emails from your domain.',
    })
  }

  if (!hasDMARC) {
    score -= 35
    findings.push({
      severity: 'high',
      title: 'Missing DMARC record',
      description:
        'No DMARC record found. Without DMARC, spoofed emails from your domain cannot be rejected by receivers.',
    })
  }

  if (!hasDNSSEC) {
    score -= 30
    findings.push({
      severity: 'medium',
      title: 'DNSSEC not enabled',
      description:
        'DNSSEC is not enabled. DNS responses can be spoofed, redirecting users to malicious servers.',
    })
  }

  if (hasDKIM) {
    info.push('DKIM detected on a common selector')
  } else {
    info.push(
      `DKIM not detected on common selectors (${DKIM_SELECTORS.join(', ')}). A custom selector may be in use - verification not penalized.`,
    )
  }

  return {
    name: 'DNS Security',
    score: Math.max(0, score),
    findings,
    ...(info.length > 0 ? { info } : {}),
  }
}
