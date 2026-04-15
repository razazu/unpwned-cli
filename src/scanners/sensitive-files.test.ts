import { describe, it, expect, vi, beforeEach } from 'vitest'
import { scanSensitiveFiles } from './sensitive-files.js'

function mockFetchByPath(statusMap: Record<string, number>) {
  return vi.fn().mockImplementation((url: string) => {
    for (const [path, status] of Object.entries(statusMap)) {
      if (url.endsWith(path)) {
        return Promise.resolve({ status, headers: new Headers() })
      }
    }
    return Promise.resolve({ status: 404, headers: new Headers() })
  })
}

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

  it('returns critical finding and score 70 when .env is exposed', async () => {
    vi.stubGlobal('fetch', mockFetchByPath({ '/.env': 200 }))

    const result = await scanSensitiveFiles('https://example.com')

    expect(result.score).toBe(70)
    expect(result.findings).toHaveLength(1)
    expect(result.findings[0].severity).toBe('critical')
    expect(result.findings[0].title).toBe('Exposed: /.env')
  })

  it('returns multiple findings and low score when many files exposed', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetchByPath({
        '/.env': 200,
        '/.git/config': 200,
        '/phpinfo.php': 200,
        '/package.json': 200,
        '/.DS_Store': 200,
      })
    )

    const result = await scanSensitiveFiles('https://example.com')

    expect(result.findings).toHaveLength(5)
    expect(result.score).toBe(Math.max(0, 100 - 30 - 30 - 20 - 10 - 5))
    expect(result.score).toBe(5)
  })

  it('adds security.txt to info when present', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetchByPath({ '/.well-known/security.txt': 200 })
    )

    const result = await scanSensitiveFiles('https://example.com')

    expect(result.score).toBe(100)
    expect(result.findings).toHaveLength(0)
    expect(result.info).toContain('security.txt found at /.well-known/security.txt')
  })

  it('handles network errors gracefully without crashing', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockRejectedValue(new Error('Network error'))
    )

    const result = await scanSensitiveFiles('https://example.com')

    expect(result.name).toBe('Sensitive Files')
    expect(result.score).toBe(100)
    expect(result.findings).toHaveLength(0)
  })

  it('floors score at 0 when deductions exceed 100', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetchByPath({
        '/.env': 200,
        '/.env.local': 200,
        '/.git/config': 200,
        '/wp-config.php': 200,
      })
    )

    const result = await scanSensitiveFiles('https://example.com')

    expect(result.findings).toHaveLength(4)
    expect(result.score).toBe(0)
  })
})
