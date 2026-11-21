import { blockedResult, fetchPage } from './interference.js'
import { evaluateCookies, scanCookies } from './scanners/cookies.js'
import { evaluateCORS, scanCORS } from './scanners/cors.js'
import { evaluateHeaders, scanHeaders } from './scanners/headers.js'
import { scanSensitiveFiles } from './scanners/sensitive-files.js'
import { detectTechStack, scanTechStack, techStackResult } from './scanners/tech-stack.js'
import type { ScanInterference, ScanResult } from './types.js'

export const HTTP_SCANNER_NAMES = ['Headers', 'Cookies', 'CORS', 'Sensitive Files', 'Tech Stack'] as const

export interface HttpScanOutcome {
  results: ScanResult[]
  interference: ScanInterference | null
}

interface CheckedResult {
  result: ScanResult
  interference: ScanInterference | null
}

async function scanCORSChecked(url: string): Promise<CheckedResult> {
  const page = await fetchPage(url, { headers: { Origin: 'https://evil.com' } })
  if (!page) return { result: await scanCORS(url), interference: null }
  if (page.interference) return { result: blockedResult('CORS'), interference: page.interference }
  return { result: evaluateCORS(page.response.headers), interference: null }
}

async function scanTechStackChecked(url: string): Promise<CheckedResult> {
  const page = await fetchPage(url, { headers: { 'User-Agent': 'unpwned-cli/1.0' } })
  if (!page) return { result: await scanTechStack(url), interference: null }
  if (page.interference) return { result: blockedResult('Tech Stack'), interference: page.interference }
  return { result: techStackResult(detectTechStack(page.response.headers, page.body)), interference: null }
}

async function scanSensitiveFilesChecked(url: string): Promise<CheckedResult> {
  const result = await scanSensitiveFiles(url)
  const after = await fetchPage(url)
  if (after?.interference) return { result: blockedResult('Sensitive Files'), interference: after.interference }
  return { result, interference: null }
}

export async function runHttpScanners(url: string): Promise<HttpScanOutcome> {
  const page = await fetchPage(url)

  if (page?.interference) {
    return {
      results: HTTP_SCANNER_NAMES.map((name) => blockedResult(name)),
      interference: page.interference,
    }
  }

  const [headers, cookies, cors, files, tech] = await Promise.all([
    page ? evaluateHeaders(page.response.headers) : scanHeaders(url),
    page ? evaluateCookies(url, page.response.headers) : scanCookies(url),
    scanCORSChecked(url),
    scanSensitiveFilesChecked(url),
    scanTechStackChecked(url),
  ])

  return {
    results: [headers, cookies, cors.result, files.result, tech.result],
    interference: cors.interference ?? files.interference ?? tech.interference,
  }
}
