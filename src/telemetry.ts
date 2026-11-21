import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

const TELEMETRY_URL = 'https://www.unpwned.io/api/cli/telemetry'

const FIRST_RUN_NOTICE =
  '\n  Anonymous telemetry is enabled to help improve UNPWNED.' +
  '\n  No URLs, domains, or IPs are collected.' +
  '\n  Disable anytime: unpwned telemetry disable\n'

function configDir(): string {
  return join(homedir(), '.unpwned')
}

function configFile(): string {
  return join(configDir(), 'config.json')
}

interface TelemetryPayload {
  cli_version: string
  node_version: string
  os: string
  score: number
  grade: string
  duration_ms: number
  findings: {
    critical: number
    high: number
    medium: number
    low: number
  }
  scanners_passed: number
  scanners_failed: number
}

function getConfig(): { telemetry: boolean } {
  try {
    if (!existsSync(configFile())) return { telemetry: true }
    const content = readFileSync(configFile(), 'utf-8')
    return JSON.parse(content)
  } catch {
    return { telemetry: true }
  }
}

function setConfig(config: { telemetry: boolean }): void {
  try {
    if (!existsSync(configDir())) {
      mkdirSync(configDir(), { recursive: true })
    }
    writeFileSync(configFile(), JSON.stringify(config, null, 2))
  } catch {
    // Silently fail
  }
}

export function isFirstRun(): boolean {
  return !existsSync(configFile())
}

export function showFirstRunNotice(
  telemetryRequested: boolean,
  write: (message: string) => void = (message) => {
    process.stderr.write(`${message}\n`)
  },
): boolean {
  if (!telemetryRequested || !isTelemetryEnabled() || !isFirstRun()) return false

  write(FIRST_RUN_NOTICE)
  setConfig({ telemetry: true })
  return true
}

export function isTelemetryEnabled(): boolean {
  if (process.env.UNPWNED_TELEMETRY === '0' || process.env.DO_NOT_TRACK === '1') {
    return false
  }
  return getConfig().telemetry
}

export function enableTelemetry(): void {
  setConfig({ telemetry: true })
}

export function disableTelemetry(): void {
  setConfig({ telemetry: false })
}

export async function sendTelemetry(payload: TelemetryPayload): Promise<void> {
  if (!isTelemetryEnabled()) return

  try {
    await fetch(TELEMETRY_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(3000),
    })
  } catch {}
}
