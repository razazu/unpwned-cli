import { describe, it, expect, vi, beforeEach } from 'vitest'
import { scanTechStack } from './tech-stack.js'

function mockFetch(
  headers: Record<string, string>,
  body: string = ''
) {
  return vi.fn().mockResolvedValue({
    headers: new Headers(headers),
    text: () => Promise.resolve(body),
  })
}

beforeEach(() => {
  vi.restoreAllMocks()
})

describe('scanTechStack', () => {
  it('detects X-Powered-By: Express in info', async () => {
    vi.stubGlobal('fetch', mockFetch({ 'x-powered-by': 'Express' }))

    const result = await scanTechStack('https://example.com')

    expect(result.name).toBe('Tech Stack')
    expect(result.score).toBe(100)
    expect(result.findings).toHaveLength(0)
    expect(result.info).toContain('Express')
  })

  it('detects Next.js from __NEXT_DATA__ in HTML', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({}, '<script id="__NEXT_DATA__">{"props":{}}</script>')
    )

    const result = await scanTechStack('https://example.com')

    expect(result.score).toBe(100)
    expect(result.info).toContain('Next.js')
  })

  it('detects multiple technologies', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch(
        { server: 'nginx', 'x-powered-by': 'Express' },
        '<div id="__NEXT_DATA__"></div><link href="/wp-content/themes/style.css">'
      )
    )

    const result = await scanTechStack('https://example.com')

    expect(result.score).toBe(100)
    expect(result.findings).toHaveLength(0)
    expect(result.info).toContain('Express')
    expect(result.info).toContain('nginx')
    expect(result.info).toContain('Next.js')
    expect(result.info).toContain('WordPress')
  })

  it('returns score 100 with empty info when no tech detected', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({}, '<html><body>Hello</body></html>')
    )

    const result = await scanTechStack('https://example.com')

    expect(result.name).toBe('Tech Stack')
    expect(result.score).toBe(100)
    expect(result.findings).toHaveLength(0)
    expect(result.info).toHaveLength(0)
  })

  it('returns score 100 with empty info on fetch error', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockRejectedValue(new Error('Network error'))
    )

    const result = await scanTechStack('https://down.example.com')

    expect(result.name).toBe('Tech Stack')
    expect(result.score).toBe(100)
    expect(result.findings).toHaveLength(0)
    expect(result.info).toHaveLength(0)
  })
})
