import type { Finding, ScanResult, Severity } from '../types.js'

interface SensitivePath {
  path: string
  severity: Severity
  points: number
  desc: string
  validate: (body: Buffer, contentType: string) => boolean
}

function isLikelyHtml(body: Buffer, contentType: string): boolean {
  if (contentType.toLowerCase().includes('text/html')) return true
  const head = body.subarray(0, 256).toString('utf-8').trimStart().toLowerCase()
  return (
    head.startsWith('<!doctype html') ||
    head.startsWith('<html') ||
    head.startsWith('<head') ||
    head.startsWith('<body')
  )
}

function validateEnv(body: Buffer, contentType: string): boolean {
  if (isLikelyHtml(body, contentType)) return false
  const text = body.toString('utf-8')
  return /^[A-Z_][A-Z0-9_]*\s*=/m.test(text)
}

function validateGitConfig(body: Buffer, contentType: string): boolean {
  if (isLikelyHtml(body, contentType)) return false
  const text = body.toString('utf-8').trimStart()
  if (!text.startsWith('[')) return false
  return /\[(core|remote|branch|user|alias|http|push|pull|diff|filter)\b/i.test(text)
}

function validateWpConfig(body: Buffer, contentType: string): boolean {
  if (isLikelyHtml(body, contentType)) return false
  const text = body.toString('utf-8')
  return text.includes('<?php') && (text.includes('DB_NAME') || /define\s*\(/.test(text))
}

function validatePhpInfo(body: Buffer): boolean {
  const text = body.toString('utf-8')
  return text.includes('phpinfo()') || /PHP\s+Version\s*[:<]/i.test(text)
}

function validateServerStatus(body: Buffer): boolean {
  const text = body.toString('utf-8')
  return /Apache\s+Server\s+Status/i.test(text) || /\b(BusyWorkers|IdleWorkers)\b/.test(text)
}

function validatePackageJson(body: Buffer, contentType: string): boolean {
  if (isLikelyHtml(body, contentType)) return false
  const text = body.toString('utf-8').trimStart()
  if (!text.startsWith('{')) return false
  return /"(name|version|dependencies|devDependencies|scripts)"\s*:/.test(text)
}

function validateHtaccess(body: Buffer, contentType: string): boolean {
  if (isLikelyHtml(body, contentType)) return false
  const text = body.toString('utf-8')
  return /^\s*(RewriteEngine|RewriteRule|AuthType|AuthUserFile|Options|AllowOverride|<Files|Require\s|Order\s|Deny\s|Allow\s|DirectoryIndex|ErrorDocument)\b/mi.test(
    text,
  )
}

function validateDSStore(body: Buffer): boolean {
  if (body.length < 8) return false
  return (
    body[0] === 0x00 &&
    body[1] === 0x00 &&
    body[2] === 0x00 &&
    body[3] === 0x01 &&
    body[4] === 0x42 &&
    body[5] === 0x75 &&
    body[6] === 0x64 &&
    body[7] === 0x31
  )
}

const SENSITIVE_PATHS: SensitivePath[] = [
  {
    path: '/.env',
    severity: 'critical',
    points: 30,
    desc: 'Environment variables file exposed',
    validate: validateEnv,
  },
  {
    path: '/.env.local',
    severity: 'critical',
    points: 30,
    desc: 'Local environment file exposed',
    validate: validateEnv,
  },
  {
    path: '/.git/config',
    severity: 'critical',
    points: 30,
    desc: 'Git configuration exposed',
    validate: validateGitConfig,
  },
  {
    path: '/wp-config.php',
    severity: 'critical',
    points: 30,
    desc: 'WordPress config exposed',
    validate: validateWpConfig,
  },
  {
    path: '/phpinfo.php',
    severity: 'high',
    points: 20,
    desc: 'PHP info page exposed',
    validate: validatePhpInfo,
  },
  {
    path: '/server-status',
    severity: 'high',
    points: 20,
    desc: 'Server status page exposed',
    validate: validateServerStatus,
  },
  {
    path: '/package.json',
    severity: 'medium',
    points: 10,
    desc: 'Package manifest exposed',
    validate: validatePackageJson,
  },
  {
    path: '/.htaccess',
    severity: 'medium',
    points: 10,
    desc: 'Apache config exposed',
    validate: validateHtaccess,
  },
  {
    path: '/.DS_Store',
    severity: 'low',
    points: 5,
    desc: 'macOS metadata file exposed',
    validate: validateDSStore,
  },
]

async function probePath(
  baseUrl: string,
  check: SensitivePath,
): Promise<boolean> {
  try {
    const res = await fetch(`${baseUrl}${check.path}`, {
      method: 'GET',
      headers: { Range: 'bytes=0-2047' },
      redirect: 'follow',
      signal: AbortSignal.timeout(4000),
    })
    if (res.status !== 200 && res.status !== 206) return false
    const buf = Buffer.from(await res.arrayBuffer())
    if (buf.length === 0) return false
    const contentType = res.headers.get('content-type') ?? ''
    return check.validate(buf, contentType)
  } catch {
    return false
  }
}

export async function scanSensitiveFiles(url: string): Promise<ScanResult> {
  const baseUrl = url.replace(/\/+$/, '')
  const findings: Finding[] = []
  const info: string[] = []
  let deductions = 0

  const checks = SENSITIVE_PATHS.map(async (check) => ({
    exposed: await probePath(baseUrl, check),
    check,
  }))

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
