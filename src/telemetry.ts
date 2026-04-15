import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

const CONFIG_DIR = join(homedir(), '.unpwned')
const CONFIG_FILE = join(CONFIG_DIR, 'config.json')
const TELEMETRY_URL = 'https://www.unpwned.io/api/cli/telemetry'

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
    if (!existsSync(CONFIG_FILE)) return { telemetry: true }
    const content = readFileSync(CONFIG_FILE, 'utf-8')
    return JSON.parse(content)
  } catch {
    return { telemetry: true }
  }
}

function setConfig(config: { telemetry: boolean }): void {
  try {
    if (!existsSync(CONFIG_DIR)) {
      mkdirSync(CONFIG_DIR, { recursive: true })
    }
    writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2))
  } catch {
    // Silently fail
  }
}

export function isFirstRun(): boolean {
  return !existsSync(CONFIG_FILE)
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
