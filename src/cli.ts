import { Command } from 'commander'
import ora from 'ora'
import { scanSSL } from './scanners/ssl.js'
import { scanDNS } from './scanners/dns.js'
import { scanBreaches } from './scanners/breaches.js'
import { calculateScore, getGrade } from './scoring.js'
import { printReport, printJson } from './output.js'
import { HTTP_SCANNER_NAMES, runHttpScanners } from './http-scan.js'
import type { HttpScanOutcome } from './http-scan.js'
import { describeInterference } from './interference.js'
import { sendTelemetry, enableTelemetry, disableTelemetry, isTelemetryEnabled, showFirstRunNotice } from './telemetry.js'
import { VERSION } from './version.js'
import type { ScanResult, ScanReport } from './types.js'

const SCANNER_ORDER = [
  'Headers',
  'SSL/TLS',
  'DNS Security',
  'Cookies',
  'CORS',
  'Sensitive Files',
  'Tech Stack',
  'Breaches',
]

const EXIT_PASSED = 0
const EXIT_FAILED = 1
const EXIT_BLOCKED = 2

function failedResult(name: string, reason: unknown): ScanResult {
  const errorMessage = reason instanceof Error ? reason.message : String(reason)
  return {
    name,
    score: 0,
    findings: [
      {
        severity: 'critical',
        title: 'Scanner failed',
        description: `Scanner failed: ${errorMessage}`,
      },
    ],
  }
}

const program = new Command()

program
  .name('unpwned')
  .description('Website security scanner. Zero config. One command.')
  .version(VERSION)

program
  .command('scan')
  .argument('<target>', 'URL or domain to scan')
  .option('--json', 'Output results as JSON')
  .option('--no-telemetry', 'Disable telemetry for this scan')
  .action(async (target: string, options: { json?: boolean; telemetry?: boolean }) => {
    showFirstRunNotice(options.telemetry !== false)

    let url = target.replace(/\/+$/, '')
    if (!/^https?:\/\//i.test(url)) {
      url = `https://${url}`
    }

    const hostname = new URL(url).hostname

    const spinner = ora(`Scanning ${url}...`).start()
    const startTime = Date.now()

    const httpScan = runHttpScanners(url).catch(
      (reason: unknown): HttpScanOutcome => ({
        results: HTTP_SCANNER_NAMES.map((name) => failedResult(name, reason)),
        interference: null,
      }),
    )

    const directScanners: { name: string; fn: () => Promise<ScanResult> }[] = [
      { name: 'SSL/TLS', fn: () => scanSSL(hostname) },
      { name: 'DNS Security', fn: () => scanDNS(hostname) },
      { name: 'Breaches', fn: () => scanBreaches(hostname) },
    ]

    const directSettled = await Promise.allSettled(directScanners.map((s) => s.fn()))
    const { results: httpResults, interference } = await httpScan

    const byName = new Map<string, ScanResult>()
    for (const result of httpResults) {
      byName.set(result.name, result)
    }
    directSettled.forEach((result, i) => {
      const name = directScanners[i].name
      byName.set(name, result.status === 'fulfilled' ? result.value : failedResult(name, result.reason))
    })

    const results: ScanResult[] = SCANNER_ORDER.map(
      (name) => byName.get(name) ?? failedResult(name, 'no result returned'),
    )

    spinner.stop()

    const duration = Date.now() - startTime
    const overallScore = calculateScore(results)
    const grade = getGrade(overallScore)

    const report: ScanReport = {
      target: url,
      timestamp: new Date().toISOString(),
      scanners: results,
      overallScore,
      grade,
      duration,
      ...(interference && { interference }),
    }

    if (options.telemetry !== false) {
      await sendTelemetry({
        cli_version: VERSION,
        node_version: process.version,
        os: process.platform,
        score: overallScore,
        grade,
        duration_ms: duration,
        findings: {
          critical: results.reduce((sum, r) => sum + r.findings.filter(f => f.severity === 'critical').length, 0),
          high: results.reduce((sum, r) => sum + r.findings.filter(f => f.severity === 'high').length, 0),
          medium: results.reduce((sum, r) => sum + r.findings.filter(f => f.severity === 'medium').length, 0),
          low: results.reduce((sum, r) => sum + r.findings.filter(f => f.severity === 'low').length, 0),
        },
        scanners_passed: results.filter(r => !r.skipped && r.score === 100).length,
        scanners_failed: results.filter(r => !r.skipped && r.score === 0).length,
      })
    }

    if (options.json) {
      printJson(report)
      if (interference) {
        process.stderr.write(
          `unpwned: the target blocked this scan (${describeInterference(interference)}). Results are partial.\n`,
        )
      }
    } else {
      printReport(report)
    }

    if (interference) {
      process.exit(EXIT_BLOCKED)
    }
    process.exit(overallScore >= 50 ? EXIT_PASSED : EXIT_FAILED)
  })

program
  .command('telemetry')
  .argument('<action>', 'enable or disable')
  .description('Manage anonymous telemetry')
  .action((action: string) => {
    if (action === 'disable') {
      disableTelemetry()
      console.log('Telemetry disabled. No data will be collected.')
    } else if (action === 'enable') {
      enableTelemetry()
      console.log('Telemetry enabled. Only anonymous usage data is collected.')
    } else {
      console.log(`Status: telemetry is ${isTelemetryEnabled() ? 'enabled' : 'disabled'}`)
      console.log('Usage: unpwned telemetry <enable|disable>')
    }
  })

program.parse()
