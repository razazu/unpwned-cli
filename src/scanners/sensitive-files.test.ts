import { describe, it, expect, vi, beforeEach } from 'vitest'
import { scanSensitiveFiles } from './sensitive-files.js'

interface MockResponse {
  status: number
  body?: Buffer | string
  contentType?: string
}

function makeResponse(r: MockResponse) {
  const buf =
    r.body === undefined
      ? Buffer.alloc(0)
      : typeof r.body === 'string'
        ? Buffer.from(r.body, 'utf-8')
        : r.body
  const headers = new Headers()
  if (r.contentType) headers.set('content-type', r.contentType)
  return {
    status: r.status,
    headers,
    arrayBuffer: () =>
      Promise.resolve(
        buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer,
      ),
  }
}

function mockFetchByPath(pathMap: Record<string, MockResponse>) {
  return vi.fn().mockImplementation((url: string) => {
    for (const [path, resp] of Object.entries(pathMap)) {
      if (url.endsWith(path)) {
        return Promise.resolve(makeResponse(resp))
      }
    }
    return Promise.resolve(makeResponse({ status: 404 }))
  })
}

const ENV_BODY = 'DATABASE_URL=postgres://localhost\nAPI_KEY=abc123\n'
const GIT_CONFIG_BODY = '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = git@github.com:x/y.git\n'
const WP_CONFIG_BODY = "<?php\ndefine('DB_NAME', 'mydb');\ndefine('DB_USER', 'root');"
const PHPINFO_BODY = '<title>phpinfo()</title><h1>PHP Version 8.1.0</h1>'
const SERVER_STATUS_BODY = '<title>Apache Server Status</title>BusyWorkers: 5'
const PACKAGE_JSON_BODY = '{"name":"my-app","version":"1.0.0","dependencies":{}}'
const DS_STORE_BODY = Buffer.from([0x00, 0x00, 0x00, 0x01, 0x42, 0x75, 0x64, 0x31, 0x00, 0x00])
const HTML_BODY = '<!DOCTYPE html><html><head><title>Home</title></head><body>404 page</body></html>'

beforeEach(() => {
  vi.restoreAllMocks()
})

describe('scanSensitiveFiles', () => {
  it('returns score 100 with no findings when all paths return 404', async () => {
    vi.stubGlobal('fetch', mockFetchByPath({}))

    const result = await scanSensitiveFiles('https://example.com')

    expect(result.name).toBe('Sensitive Files')
    expect(result.score).toBe(100)
    expect(result.findings).toHaveLength(0)
  })

  it('flags .env when body contains KEY=value content', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetchByPath({ '/.env': { status: 200, body: ENV_BODY } }),
    )

    const result = await scanSensitiveFiles('https://example.com')

    expect(result.score).toBe(70)
    expect(result.findings).toHaveLength(1)
    expect(result.findings[0].severity).toBe('critical')
    expect(result.findings[0].title).toBe('Exposed: /.env')
  })

  it('does NOT flag .env when server returns HTML SPA catch-all (false positive prevention)', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetchByPath({
        '/.env': { status: 200, body: HTML_BODY, contentType: 'text/html' },
      }),
    )

    const result = await scanSensitiveFiles('https://example.com')

    expect(result.score).toBe(100)
    expect(result.findings).toHaveLength(0)
  })

  it('does NOT flag .env when body is empty (HEAD-like 200 with no content)', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetchByPath({ '/.env': { status: 200, body: '' } }),
    )

    const result = await scanSensitiveFiles('https://example.com')

    expect(result.score).toBe(100)
    expect(result.findings).toHaveLength(0)
  })

  it('accepts partial content response (206) with Range', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetchByPath({ '/.env': { status: 206, body: ENV_BODY } }),
    )

    const result = await scanSensitiveFiles('https://example.com')

    expect(result.score).toBe(70)
    expect(result.findings).toHaveLength(1)
  })

  it('validates .git/config via INI section header', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetchByPath({ '/.git/config': { status: 200, body: GIT_CONFIG_BODY } }),
    )

    const result = await scanSensitiveFiles('https://example.com')

    expect(result.score).toBe(70)
    expect(result.findings[0].title).toBe('Exposed: /.git/config')
  })

  it('validates wp-config.php via <?php + DB_NAME signature', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetchByPath({ '/wp-config.php': { status: 200, body: WP_CONFIG_BODY } }),
    )

    const result = await scanSensitiveFiles('https://example.com')

    expect(result.findings[0].title).toBe('Exposed: /wp-config.php')
  })

  it('validates phpinfo.php via phpinfo signature', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetchByPath({ '/phpinfo.php': { status: 200, body: PHPINFO_BODY } }),
    )

    const result = await scanSensitiveFiles('https://example.com')

    expect(result.findings[0].title).toBe('Exposed: /phpinfo.php')
  })

  it('validates server-status via Apache signature', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetchByPath({ '/server-status': { status: 200, body: SERVER_STATUS_BODY } }),
    )

    const result = await scanSensitiveFiles('https://example.com')

    expect(result.findings[0].title).toBe('Exposed: /server-status')
  })

  it('validates package.json via JSON structure', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetchByPath({ '/package.json': { status: 200, body: PACKAGE_JSON_BODY } }),
    )

    const result = await scanSensitiveFiles('https://example.com')

    expect(result.findings[0].title).toBe('Exposed: /package.json')
  })

  it('validates .DS_Store via binary signature', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetchByPath({ '/.DS_Store': { status: 200, body: DS_STORE_BODY } }),
    )

    const result = await scanSensitiveFiles('https://example.com')

    expect(result.score).toBe(95)
    expect(result.findings[0].title).toBe('Exposed: /.DS_Store')
  })

  it('does NOT flag .DS_Store when body is arbitrary HTML', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetchByPath({
        '/.DS_Store': { status: 200, body: HTML_BODY, contentType: 'text/html' },
      }),
    )

    const result = await scanSensitiveFiles('https://example.com')

    expect(result.score).toBe(100)
    expect(result.findings).toHaveLength(0)
  })

  it('accumulates multiple real findings', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetchByPath({
        '/.env': { status: 200, body: ENV_BODY },
        '/.git/config': { status: 200, body: GIT_CONFIG_BODY },
        '/phpinfo.php': { status: 200, body: PHPINFO_BODY },
        '/package.json': { status: 200, body: PACKAGE_JSON_BODY },
        '/.DS_Store': { status: 200, body: DS_STORE_BODY },
      }),
    )

    const result = await scanSensitiveFiles('https://example.com')

    expect(result.findings).toHaveLength(5)
    expect(result.score).toBe(Math.max(0, 100 - 30 - 30 - 20 - 10 - 5))
    expect(result.score).toBe(5)
  })

  it('adds security.txt to info when present', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetchByPath({
        '/.well-known/security.txt': { status: 200 },
      }),
    )

    const result = await scanSensitiveFiles('https://example.com')

    expect(result.score).toBe(100)
    expect(result.findings).toHaveLength(0)
    expect(result.info).toContain('security.txt found at /.well-known/security.txt')
  })

  it('handles network errors gracefully without crashing', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('Network error')))

    const result = await scanSensitiveFiles('https://example.com')

    expect(result.name).toBe('Sensitive Files')
    expect(result.score).toBe(100)
    expect(result.findings).toHaveLength(0)
  })

  it('floors score at 0 when deductions exceed 100', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetchByPath({
        '/.env': { status: 200, body: ENV_BODY },
        '/.env.local': { status: 200, body: ENV_BODY },
        '/.git/config': { status: 200, body: GIT_CONFIG_BODY },
        '/wp-config.php': { status: 200, body: WP_CONFIG_BODY },
      }),
    )

    const result = await scanSensitiveFiles('https://example.com')

    expect(result.findings).toHaveLength(4)
    expect(result.score).toBe(0)
  })
})
