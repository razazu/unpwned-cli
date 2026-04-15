import type { Finding, ScanResult } from '../types.js'

export async function scanCORS(url: string): Promise<ScanResult> {
  let response: Response

  try {
    response = await fetch(url, {
      headers: { 'Origin': 'https://evil.com' },
      redirect: 'follow',
      signal: AbortSignal.timeout(10000),
    })
  } catch {
    return {
      name: 'CORS',
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

  const acao = response.headers.get('access-control-allow-origin')
  const acac = response.headers.get('access-control-allow-credentials')

  if (acao === '*') {
    score -= 30
    findings.push({
      severity: 'medium',
      title: 'Wildcard CORS policy allows any origin',
      description:
        'The server returns Access-Control-Allow-Origin: *, allowing any website to read responses. This can expose sensitive data to malicious sites.',
    })
  } else if (acao === 'https://evil.com') {
    const reflectsCredentials = acac?.toLowerCase() === 'true'

    if (reflectsCredentials) {
      score -= 70
      findings.push({
        severity: 'critical',
        title: 'CORS allows credentials from any origin',
        description:
          'The server reflects arbitrary origins and allows credentials. Attackers can steal authenticated data from any origin using cross-site requests.',
      })
    } else {
      score -= 50
      findings.push({
        severity: 'high',
        title: 'CORS reflects arbitrary origins',
        description:
          'The server reflects the Origin header back in Access-Control-Allow-Origin, allowing any website to read responses from this domain.',
      })
    }
  }

  return {
    name: 'CORS',
    score: Math.max(0, score),
    findings,
  }
}
