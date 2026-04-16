import chalk from 'chalk'
import type { ScanReport, ScanResult, Severity } from './types.js'

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
}

function colorScore(score: number, text: string): string {
  if (score >= 80) return chalk.green(text)
  if (score >= 50) return chalk.yellow(text)
  return chalk.red(text)
}

function colorGrade(grade: string): string {
  if (grade === 'A+' || grade === 'A' || grade === 'B') return chalk.green(grade)
  if (grade === 'C') return chalk.yellow(grade)
  if (grade === 'F') return chalk.red.bold(grade)
  return chalk.red(grade)
}

function colorSeverity(severity: Severity): string {
  const label = severity.toUpperCase().padEnd(10)
  switch (severity) {
    case 'critical':
      return chalk.red.bold(label)
    case 'high':
      return chalk.red(label)
    case 'medium':
      return chalk.yellow(label)
    case 'low':
      return chalk.blue(label)
    case 'info':
      return chalk.gray(label)
  }
}

function progressBar(score: number): string {
  const filled = Math.round(score / 10)
  const empty = 10 - filled
  return colorScore(score, '\u2588'.repeat(filled) + '\u2591'.repeat(empty))
}

function formatScannerLine(scanner: ScanResult): string {
  const name = scanner.name.padEnd(16)

  if (scanner.name === 'Tech Stack') {
    const techList = scanner.info && scanner.info.length > 0 ? scanner.info.join(', ') : 'Unknown'
    return `  ${chalk.white(name)}${techList}`
  }

  if (scanner.name === 'Breaches') {
    if (scanner.findings.length === 0) {
      return `  ${chalk.white(name)}${chalk.green('No known breaches')}`
    }
    return `  ${chalk.white(name)}${chalk.red.bold(`${scanner.findings.length} breach${scanner.findings.length !== 1 ? 'es' : ''} found!`)}`
  }

  const bar = progressBar(scanner.score)
  const scoreText = colorScore(scanner.score, `${String(scanner.score).padStart(3)}/100`)
  const issueCount = scanner.findings.length

  let status: string
  if (issueCount === 0) {
    status = chalk.green('[PASS]')
  } else {
    status = `[${issueCount} issue${issueCount === 1 ? '' : 's'}]`
  }

  return `  ${chalk.white(name)}${bar}  ${scoreText}  ${status}`
}

export function printReport(report: ScanReport): void {
  const width = 44

  console.log()
  console.log(`  ${chalk.cyan('\u2554' + '\u2550'.repeat(width) + '\u2557')}`)
  console.log(`  ${chalk.cyan('\u2551')}   ${chalk.bold.white('UNPWNED Security Scanner v1.0')}${' '.repeat(width - 32)}${chalk.cyan('\u2551')}`)
  console.log(`  ${chalk.cyan('\u255a' + '\u2550'.repeat(width) + '\u255d')}`)
  console.log()

  console.log(`  ${chalk.gray('Target:')} ${chalk.white(report.target)}`)
  const durationSec = report.duration / 1000
  console.log(`  ${chalk.gray('Scanned in')} ${chalk.white(durationSec.toFixed(1) + 's')}`)
  console.log()

  for (const scanner of report.scanners) {
    console.log(formatScannerLine(scanner))
  }

  console.log()
  const divider = '\u2500'.repeat(44)
  console.log(`  ${chalk.gray(divider)}`)
  console.log(`  ${chalk.bold.white('Overall Score:')} ${colorScore(report.overallScore, `${report.overallScore}/100`)}  ${chalk.bold.white('Grade:')} ${colorGrade(report.grade)}`)
  console.log(`  ${chalk.gray(divider)}`)

  const allFindings = report.scanners
    .flatMap((s) => s.findings)
    .filter((f) => f.severity !== 'info')
    .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity])

  if (allFindings.length > 0) {
    console.log()
    console.log(`  ${chalk.bold.white('ISSUES FOUND:')}`)
    console.log()

    for (const finding of allFindings) {
      console.log(`  ${colorSeverity(finding.severity)}${finding.title}`)
    }
  }

  const issueCount = allFindings.length
  if (issueCount > 0) {
    console.log()
    const boxWidth = 45
    const border = chalk.gray('\u2502')
    console.log(`  ${chalk.gray('\u250c' + '\u2500'.repeat(boxWidth) + '\u2510')}`)
    const headline = `${issueCount} ${issueCount === 1 ? 'vulnerability needs' : 'vulnerabilities need'} your attention`
    const pad1 = Math.max(0, boxWidth - headline.length)
    console.log(`  ${border}  ${chalk.bold.white(headline)}${' '.repeat(pad1 - 2)}${border}`)
    console.log(`  ${border}${' '.repeat(boxWidth)}${border}`)
    const features = [
      '\u25b8 Step-by-step fix instructions',
      '\u25b8 PDF security report',
      '\u25b8 SOC2 / GDPR / OWASP compliance',
      '\u25b8 AI-powered remediation',
    ]
    for (const feat of features) {
      const pad = Math.max(0, boxWidth - feat.length)
      console.log(`  ${border}  ${chalk.green(feat)}${' '.repeat(pad - 2)}${border}`)
    }
    console.log(`  ${border}${' '.repeat(boxWidth)}${border}`)
    const cta = 'Scan deeper: unpwned.io?ref=cli'
    const pad2 = Math.max(0, boxWidth - cta.length)
    console.log(`  ${border}  ${chalk.cyan(cta)}${' '.repeat(pad2 - 2)}${border}`)
    console.log(`  ${chalk.gray('\u2514' + '\u2500'.repeat(boxWidth) + '\u2518')}`)
  } else {
    console.log()
    console.log(`  ${chalk.green.bold('\u2713 No vulnerabilities found. Your site looks solid.')}`)
    console.log(`  ${chalk.gray('Deep scan available at:')} ${chalk.cyan('unpwned.io?ref=cli')}`)
  }
  console.log()
}

export function printJson(report: ScanReport): void {
  console.log(JSON.stringify(report, null, 2))
}
