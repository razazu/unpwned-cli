import type { Finding, ScanResult, Severity } from '../types.js'

interface SensitivePath {
  path: string
  severity: Severity
  points: number
  desc: string
}

const SENSITIVE_PATHS: SensitivePath[] = [
  { path: '/.env', severity: 'critical', points: 30, desc: 'Environment variables file exposed' },
  { path: '/.env.local', severity: 'critical', points: 30, desc: 'Local environment file exposed' },
  { path: '/.git/config', severity: 'critical', points: 30, desc: 'Git configuration exposed' },
  { path: '/wp-config.php', severity: 'critical', points: 30, desc: 'WordPress config exposed' },
  { path: '/phpinfo.php', severity: 'high', points: 20, desc: 'PHP info page exposed' },
  { path: '/server-status', severity: 'high', points: 20, desc: 'Server status page exposed' },
  { path: '/package.json', severity: 'medium', points: 10, desc: 'Package manifest exposed' },
  { path: '/.htaccess', severity: 'medium', points: 10, desc: 'Apache config exposed' },
  { path: '/.DS_Store', severity: 'low', points: 5, desc: 'macOS metadata file exposed' },
]

export async function scanSensitiveFiles(url: string): Promise<ScanResult> {
  const baseUrl = url.replace(/\/+$/, '')
  const findings: Finding[] = []
  const info: string[] = []
  let deductions = 0

  const checks = SENSITIVE_PATHS.map(async (check) => {
    try {
      const response = await fetch(`${baseUrl}${check.path}`, {
        method: 'HEAD',
        redirect: 'follow',
        signal: AbortSignal.timeout(3000),
      })
      if (response.status === 200) {
        return { exposed: true, check }
      }
    } catch {
      // Network errors are not findings
    }
    return { exposed: false, check }
  })

  const securityTxtCheck = fetch(`${baseUrl}/.well-known/security.txt`, {
    method: 'HEAD',
    redirect: 'follow',
    signal: AbortSignal.timeout(3000),
  })
    .then((r) => r.status === 200)
    .catch(() => false)

  const [results, hasSecurityTxt] = await Promise.all([
    Promise.allSettled(checks),
    securityTxtCheck,
  ])

  for (const result of results) {
    if (result.status === 'fulfilled' && result.value.exposed) {
      const { check } = result.value
      deductions += check.points
      findings.push({
        severity: check.severity,
        title: `Exposed: ${check.path}`,
        description: check.desc,
      })
    }
  }

  if (hasSecurityTxt) {
    info.push('security.txt found at /.well-known/security.txt')
  }

  const score = Math.max(0, 100 - deductions)

  return {
    name: 'Sensitive Files',
    score,
    findings,
    ...(info.length > 0 ? { info } : {}),
  }
}
