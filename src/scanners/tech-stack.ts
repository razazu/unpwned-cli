import type { ScanResult } from '../types.js'

export async function scanTechStack(url: string): Promise<ScanResult> {
  const info: string[] = []

  try {
    const response = await fetch(url, {
      headers: { 'User-Agent': 'unpwned-cli/1.0' },
      redirect: 'follow',
    })

    const headers = response.headers

    const poweredBy = headers.get('x-powered-by')
    if (poweredBy) info.push(poweredBy)

    const server = headers.get('server')
    if (server) info.push(server)

    const generator = headers.get('x-generator')
    if (generator) info.push(generator)

    const via = headers.get('via')
    if (via) {
      if (/vercel/i.test(via)) info.push('Vercel')
      else if (/cloudflare/i.test(via)) info.push('Cloudflare')
      else if (/fastly/i.test(via)) info.push('Fastly')
      else info.push(via)
    }

    const html = await response.text()

    if (/__NEXT_DATA__/.test(html) || /_next\/static/.test(html)) {
      info.push('Next.js')
    }

    if (/ng-version/.test(html) || /ng-app/.test(html)) {
      info.push('Angular')
    }

    if (/__nuxt/.test(html) || /__NUXT__/.test(html)) {
      info.push('Nuxt.js')
    }

    if (/data-reactroot/.test(html) || /_reactRootContainer/.test(html)) {
      info.push('React')
    }

    if (/__SVELTE__/.test(html) || /svelte/.test(html)) {
      info.push('Svelte')
    }

    if (/wp-content/.test(html) || /wp-includes/.test(html)) {
      info.push('WordPress')
    }

    const metaGenerator = html.match(
      /<meta\s+name=["']generator["']\s+content=["']([^"']+)["']/i
    )
    if (metaGenerator) {
      info.push(metaGenerator[1])
    }
  } catch {
    // Graceful failure
  }

  return {
    name: 'Tech Stack',
    score: 100,
    findings: [],
    info,
  }
}
