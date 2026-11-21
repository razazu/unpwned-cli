import { describeConnectionFailure, isTransientFailure } from './connection.js'
import { blockedResult, requestPage } from './interference.js'
import type { FetchedPage } from './interference.js'
import { evaluateCookies } from './scanners/cookies.js'
import { evaluateCORS } from './scanners/cors.js'
import { evaluateHeaders } from './scanners/headers.js'
import { scanSensitiveFiles } from './scanners/sensitive-files.js'
import { detectTechStack, techStackResult } from './scanners/tech-stack.js'
import { TargetError } from './target.js'
import type { ScanInterference, ScanResult } from './types.js'

export const HTTP_SCANNER_NAMES = ['Headers', 'Cookies', 'CORS', 'Sensitive Files', 'Tech Stack'] as const

const RETRY_DELAY_MS = 500

export interface HttpScanOutcome {
  results: ScanResult[]
  interference: ScanInterference | null
}

interface CheckedResult {
  result: ScanResult
  interference: ScanInterference | null
}

type Stage = 'first-request' | 'during-scan'

function connectionError(url: string, error: unknown, stage: Stage): TargetError {
  const reason = describeConnectionFailure(error)
  return new TargetError(
    stage === 'first-request'
      ? `Could not connect to ${url}: ${reason}.`
      : `${url} stopped responding during the scan: ${reason}. A firewall may have blocked the scanner.`,
  )
}

async function loadPage(url: string, stage: Stage, init: RequestInit = {}): Promise<FetchedPage> {
  try {
    return await requestPage(url, init)
  } catch (error) {
    if (!isTransientFailure(error)) throw connectionError(url, error, stage)
  }

  await new Promise((resolve) => setTimeout(resolve, RETRY_DELAY_MS))

  try {
    return await requestPage(url, init)
  } catch (error) {
    throw connectionError(url, error, stage)
  }
}

async function scanCORSChecked(url: string): Promise<CheckedResult> {
  const page = await loadPage(url, 'during-scan', { headers: { Origin: 'https://evil.com' } })
  if (page.interference) return { result: blockedResult('CORS'), interference: page.interference }
  return { result: evaluateCORS(page.response.headers), interference: null }
}

async function scanTechStackChecked(url: string): Promise<CheckedResult> {
  const page = await loadPage(url, 'during-scan', { headers: { 'User-Agent': 'unpwned-cli/1.0' } })
  if (page.interference) return { result: blockedResult('Tech Stack'), interference: page.interference }
  return { result: techStackResult(detectTechStack(page.response.headers, page.body)), interference: null }
}

async function scanSensitiveFilesChecked(url: string): Promise<CheckedResult> {
  const result = await scanSensitiveFiles(url)
  const after = await loadPage(url, 'during-scan')
  if (after.interference) return { result: blockedResult('Sensitive Files'), interference: after.interference }
  return { result, interference: null }
}

export async function runHttpScanners(url: string): Promise<HttpScanOutcome> {
  const page = await loadPage(url, 'first-request')

  if (page.interference) {
    return {
      results: HTTP_SCANNER_NAMES.map((name) => blockedResult(name)),
      interference: page.interference,
    }
  }

  const [cors, files, tech] = await Promise.all([
    scanCORSChecked(url),
    scanSensitiveFilesChecked(url),
    scanTechStackChecked(url),
  ])

  return {
    results: [
      evaluateHeaders(page.response.headers),
      evaluateCookies(url, page.response.headers),
      cors.result,
      files.result,
      tech.result,
    ],
    interference: cors.interference ?? files.interference ?? tech.interference,
  }
}
