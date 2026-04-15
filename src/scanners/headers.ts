import type { Finding, ScanResult, Severity } from '../types.js'

interface HeaderCheck {
  header: string
  severity: Severity
  points: number
  description: string
}

const HEADER_CHECKS: HeaderCheck[] = [
  {
    header: 'content-security-policy',
    severity: 'high',
    points: 25,
    description: 'Controls which resources the browser is allowed to load, preventing XSS and data injection attacks.',
  },
  {
    header: 'strict-transport-security',
    severity: 'high',
    points: 25,
    description: 'Forces browsers to use HTTPS, preventing protocol downgrade attacks and cookie hijacking.',
  },
  {
    header: 'x-frame-options',
    severity: 'medium',
    points: 15,
    description: 'Prevents the page from being embedded in iframes, protecting against clickjacking attacks.',
  },
  {
    header: 'x-content-type-options',
    severity: 'medium',
    points: 15,
    description: 'Prevents browsers from MIME-sniffing the content type, reducing drive-by download attacks.',
  },
  {
    header: 'referrer-policy',
    severity: 'low',
    points: 10,
    description: 'Controls how much referrer information is sent with requests, protecting user privacy.',
  },
  {
    header: 'permissions-policy',
    severity: 'low',
    points: 10,
    description: 'Restricts which browser features and APIs the page can use, reducing the attack surface.',
  },
]

export async function scanHeaders(url: string): Promise<ScanResult> {
  let response: Response

  try {
    response = await fetch(url, {
      redirect: 'follow',
      signal: AbortSignal.timeout(10000),
    })
  } catch {
    return {
      name: 'Headers',
      score: 0,
      findings: [
        {
          severity: 'critical',
          title: 'Failed to connect',
          description: `Could not establish a connection to ${url}.`,
        },
      ],
    }
  }

  const findings: Finding[] = []
  let score = 100

  for (const check of HEADER_CHECKS) {
    const value = response.headers.get(check.header)
    if (!value) {
      score -= check.points
      findings.push({
        severity: check.severity,
        title: `Missing ${formatHeaderName(check.header)} header`,
        description: check.description,
      })
    }
  }

  return {
    name: 'Headers',
    score,
    findings,
  }
}

function formatHeaderName(header: string): string {
  return header
    .split('-')
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join('-')
}
