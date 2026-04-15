import dns from 'node:dns'
import type { Finding, ScanResult } from '../types.js'

const DKIM_SELECTORS = ['default', 'google', 'selector1', 'selector2', 'k1']

async function checkSPF(domain: string): Promise<boolean> {
  try {
    const records = await dns.promises.resolveTxt(domain)
    return records.some((parts) => parts.join('').includes('v=spf1'))
  } catch {
    return false
  }
}

async function checkDMARC(domain: string): Promise<boolean> {
  try {
    const records = await dns.promises.resolveTxt('_dmarc.' + domain)
    return records.some((parts) => parts.join('').includes('v=DMARC1'))
  } catch {
    return false
  }
}

async function checkDKIM(domain: string): Promise<boolean> {
  for (const selector of DKIM_SELECTORS) {
    try {
      const records = await dns.promises.resolveTxt(selector + '._domainkey.' + domain)
      if (records.length > 0) return true
    } catch {
      continue
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

export async function scanDNS(domain: string): Promise<ScanResult> {
  const findings: Finding[] = []
  let score = 100

  const [hasSPF, hasDMARC, hasDKIM, hasDNSSEC] = await Promise.all([
    checkSPF(domain),
    checkDMARC(domain),
    checkDKIM(domain),
    checkDNSSEC(domain),
  ])

  if (!hasSPF) {
    score -= 30
    findings.push({
      severity: 'high',
      title: 'Missing SPF record',
      description:
        'No SPF (Sender Policy Framework) record found. Attackers can spoof emails from your domain.',
    })
  }

  if (!hasDMARC) {
    score -= 30
    findings.push({
      severity: 'high',
      title: 'Missing DMARC record',
      description:
        'No DMARC record found. Without DMARC, spoofed emails from your domain cannot be rejected by receivers.',
    })
  }

  if (!hasDKIM) {
    score -= 20
    findings.push({
      severity: 'medium',
      title: 'No DKIM record found',
      description:
        'No DKIM record found for common selectors. DKIM cryptographically signs emails to prove they are unaltered.',
    })
  }

  if (!hasDNSSEC) {
    score -= 20
    findings.push({
      severity: 'medium',
      title: 'DNSSEC not enabled',
      description:
        'DNSSEC is not enabled. DNS responses can be spoofed, redirecting users to malicious servers.',
    })
  }

  return {
    name: 'DNS Security',
    score,
    findings,
  }
}
