import { describe, expect, it, vi } from 'vitest'
import { platformSuffix } from './platforms.js'
import { assertResolvable, parseTarget, TargetError } from './target.js'

describe('parseTarget', () => {
  it('adds https to a bare domain', () => {
    expect(parseTarget('example.com')).toEqual({ url: 'https://example.com', hostname: 'example.com', tlsPort: 443 })
  })

  it('keeps an explicit scheme and strips trailing slashes', () => {
    expect(parseTarget('http://example.com/')).toEqual({
      url: 'http://example.com',
      hostname: 'example.com',
      tlsPort: 443,
    })
  })

  it('uses the port of an https URL for the TLS check', () => {
    expect(parseTarget('https://example.com:8443').tlsPort).toBe(8443)
  })

  it('keeps 443 for the TLS check of an http URL with a port', () => {
    expect(parseTarget('http://127.0.0.1:3000')).toEqual({
      url: 'http://127.0.0.1:3000',
      hostname: '127.0.0.1',
      tlsPort: 443,
    })
  })

  it('removes the brackets of an IPv6 host', () => {
    expect(parseTarget('http://[::1]:8080').hostname).toBe('::1')
  })

  it('rejects input that is not a domain or URL', () => {
    expect(() => parseTarget('http://')).toThrow(TargetError)
    expect(() => parseTarget('exa mple.com')).toThrow(TargetError)
    expect(() => parseTarget('')).toThrow(TargetError)
  })
})

describe('assertResolvable', () => {
  it('passes when the host resolves', async () => {
    const resolve = vi.fn(async () => ({ address: '192.0.2.1', family: 4 }))

    await expect(assertResolvable('example.com', resolve)).resolves.toBeUndefined()
    expect(resolve).toHaveBeenCalledWith('example.com')
  })

  it('throws a clear error when the host does not resolve', async () => {
    const resolve = vi.fn(async () => {
      throw Object.assign(new Error('getaddrinfo ENOTFOUND'), { code: 'ENOTFOUND' })
    })

    await expect(assertResolvable('no-such-host.invalid', resolve)).rejects.toThrow(
      'Could not resolve no-such-host.invalid. Check the domain and try again.',
    )
    await expect(assertResolvable('no-such-host.invalid', resolve)).rejects.toBeInstanceOf(TargetError)
  })

  it('does not look up an IP address', async () => {
    const resolve = vi.fn()

    await assertResolvable('192.0.2.10', resolve)
    await assertResolvable('::1', resolve)

    expect(resolve).not.toHaveBeenCalled()
  })
})

describe('platformSuffix', () => {
  it('recognizes subdomains of hosting platforms', () => {
    expect(platformSuffix('my-app.vercel.app')).toBe('vercel.app')
    expect(platformSuffix('My-App.Netlify.App')).toBe('netlify.app')
    expect(platformSuffix('team.project.pages.dev')).toBe('pages.dev')
  })

  it('does not match custom domains or the platform domain itself', () => {
    expect(platformSuffix('example.com')).toBeNull()
    expect(platformSuffix('vercel.app')).toBeNull()
    expect(platformSuffix('notvercel.app')).toBeNull()
  })
})
