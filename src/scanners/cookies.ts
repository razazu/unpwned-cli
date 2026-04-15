import type { Finding, ScanResult } from '../types.js'

export async function scanCookies(url: string): Promise<ScanResult> {
  let response: Response

  try {
    response = await fetch(url, {
      redirect: 'follow',
      signal: AbortSignal.timeout(10000),
    })
  } catch {
    return {
      name: 'Cookies',
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

  const cookies = response.headers.getSetCookie()

  if (cookies.length === 0) {
    return {
      name: 'Cookies',
      score: 100,
      findings: [],
    }
  }

  const isHttps = url.startsWith('https')
  const findings: Finding[] = []
  let totalIssues = 0

  for (const cookie of cookies) {
    const name = cookie.split('=')[0].trim()
    const lower = cookie.toLowerCase()

    if (isHttps && !lower.includes('; secure')) {
      totalIssues++
      findings.push({
        severity: 'high',
        title: `Cookie "${name}" missing Secure flag`,
        description:
          'The Secure flag ensures the cookie is only sent over HTTPS, preventing interception over unencrypted connections.',
      })
    }

    if (!lower.includes('; httponly')) {
      totalIssues++
      findings.push({
        severity: 'medium',
        title: `Cookie "${name}" missing HttpOnly flag`,
        description:
          'The HttpOnly flag prevents JavaScript from accessing the cookie, mitigating XSS-based cookie theft.',
      })
    }

    if (!lower.includes('; samesite=')) {
      totalIssues++
      findings.push({
        severity: 'low',
        title: `Cookie "${name}" missing SameSite attribute`,
        description:
          'The SameSite attribute controls when cookies are sent with cross-site requests, helping prevent CSRF attacks.',
      })
    }
  }

  const maxIssues = cookies.length * 3
  const score = Math.max(0, Math.round(100 - (totalIssues / maxIssues) * 100))

  return {
    name: 'Cookies',
    score,
    findings,
  }
}
