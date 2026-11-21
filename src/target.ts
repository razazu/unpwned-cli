import { lookup } from 'node:dns/promises'
import { isIP } from 'node:net'

export class TargetError extends Error {}

export interface ScanTarget {
  url: string
  hostname: string
  tlsPort: number
}

export function parseTarget(input: string): ScanTarget {
  const trimmed = input.trim()
  const withScheme = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`
  const url = withScheme.replace(/\/+$/, '')

  let parsed: URL
  try {
    parsed = new URL(url)
  } catch {
    throw new TargetError(`"${input}" is not a valid domain or URL.`)
  }

  const hostname = parsed.hostname.replace(/^\[|\]$/g, '')
  if (!hostname || /\s/.test(trimmed)) {
    throw new TargetError(`"${input}" is not a valid domain or URL.`)
  }

  const tlsPort = parsed.protocol === 'https:' && parsed.port ? Number(parsed.port) : 443

  return { url, hostname, tlsPort }
}

export async function assertResolvable(
  hostname: string,
  resolve: (host: string) => Promise<unknown> = lookup,
): Promise<void> {
  if (isIP(hostname)) return

  try {
    await resolve(hostname)
  } catch {
    throw new TargetError(`Could not resolve ${hostname}. Check the domain and try again.`)
  }
}
