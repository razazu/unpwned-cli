import { Command } from 'commander'
import ora from 'ora'
import { scanHeaders } from './scanners/headers.js'
import { scanSSL } from './scanners/ssl.js'
import { scanDNS } from './scanners/dns.js'
import { scanCookies } from './scanners/cookies.js'
import { scanCORS } from './scanners/cors.js'
import { scanSensitiveFiles } from './scanners/sensitive-files.js'
import { scanTechStack } from './scanners/tech-stack.js'
import { calculateScore, getGrade } from './scoring.js'
import { printReport, printJson } from './output.js'
import type { ScanResult, ScanReport } from './types.js'

const program = new Command()

program
  .name('unpwned')
  .description('Website security scanner. Zero config. One command.')
  .version('1.0.0')

program
  .command('scan')
  .argument('<target>', 'URL or domain to scan')
  .option('--json', 'Output results as JSON')
  .action(async (target: string, options: { json?: boolean }) => {
    let url = target.replace(/\/+$/, '')
    if (!/^https?:\/\//i.test(url)) {
      url = `https://${url}`
    }

    const hostname = new URL(url).hostname

    const spinner = ora(`Scanning ${url}...`).start()
    const startTime = Date.now()

    const scannerConfigs: { name: string; fn: () => Promise<ScanResult> }[] = [
      { name: 'Headers', fn: () => scanHeaders(url) },
      { name: 'SSL/TLS', fn: () => scanSSL(hostname) },
      { name: 'DNS Security', fn: () => scanDNS(hostname) },
      { name: 'Cookies', fn: () => scanCookies(url) },
      { name: 'CORS', fn: () => scanCORS(url) },
      { name: 'Sensitive Files', fn: () => scanSensitiveFiles(url) },
      { name: 'Tech Stack', fn: () => scanTechStack(url) },
    ]

    const settled = await Promise.allSettled(
      scannerConfigs.map((s) => s.fn())
    )

    const results: ScanResult[] = settled.map((result, i) => {
      if (result.status === 'fulfilled') {
        return result.value
      }
      const errorMessage =
        result.reason instanceof Error
          ? result.reason.message
          : String(result.reason)
      return {
        name: scannerConfigs[i].name,
        score: 0,
        findings: [
          {
            severity: 'critical' as const,
            title: 'Scanner failed',
            description: `Scanner failed: ${errorMessage}`,
          },
        ],
      }
    })

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
    }

    if (options.json) {
      printJson(report)
    } else {
      printReport(report)
    }

    process.exit(overallScore >= 50 ? 0 : 1)
  })

program.parse()
