import { describe, it, expect, vi, beforeEach } from 'vitest'
import { scanSSL } from './ssl.js'

vi.mock('node:tls', () => {
  const createMockSocket = (cert: Record<string, unknown>, protocol: string) => {
    const handlers: Record<string, Function[]> = {}
    const socket = {
      on: vi.fn((event: string, handler: Function) => {
        handlers[event] = handlers[event] || []
        handlers[event].push(handler)
        return socket
      }),
      destroy: vi.fn(),
      getPeerCertificate: vi.fn(() => cert),
      getProtocol: vi.fn(() => protocol),
      _handlers: handlers,
      _triggerError: (err: Error) => {
        handlers['error']?.forEach(h => h(err))
      }
    }
    return socket
  }

  return {
    default: {
      connect: vi.fn(),
      checkServerIdentity: vi.fn()
    }
  }
})

import tls from 'node:tls'

const mockConnect = vi.mocked(tls.connect)

function setupConnect(
  cert: Record<string, unknown>,
  protocol: string,
  trust: { authorized?: boolean; authorizationError?: string } = {},
) {
  mockConnect.mockImplementation((...args: unknown[]) => {
    const callback = args[args.length - 1] as Function
    const handlers: Record<string, Function[]> = {}
    const socket = {
      on: vi.fn((event: string, handler: Function) => {
        handlers[event] = handlers[event] || []
        handlers[event].push(handler)
        return socket
      }),
      destroy: vi.fn(),
      getPeerCertificate: vi.fn(() => cert),
      getProtocol: vi.fn(() => protocol),
      authorized: trust.authorized,
      authorizationError: trust.authorizationError
    }
    setTimeout(() => callback(), 0)
    return socket as unknown as tls.TLSSocket
  })
}

function setupConnectError(errorMessage: string) {
  mockConnect.mockImplementation((...args: unknown[]) => {
    const handlers: Record<string, Function[]> = {}
    const socket = {
      on: vi.fn((event: string, handler: Function) => {
        handlers[event] = handlers[event] || []
        handlers[event].push(handler)
        return socket
      }),
      destroy: vi.fn(),
      getPeerCertificate: vi.fn(),
      getProtocol: vi.fn()
    }
    setTimeout(() => {
      handlers['error']?.forEach(h => h(new Error(errorMessage)))
    }, 0)
    return socket as unknown as tls.TLSSocket
  })
}

const mockCheckServerIdentity = vi.mocked(tls.checkServerIdentity)

function validCert(overrides: Record<string, unknown> = {}) {
  const validTo = new Date()
  validTo.setFullYear(validTo.getFullYear() + 1)
  const validFrom = new Date()
  validFrom.setFullYear(validFrom.getFullYear() - 1)
  return {
    issuer: { O: 'Example CA', CN: 'R3' },
    subject: { O: 'My Company', CN: 'example.com' },
    valid_to: validTo.toISOString(),
    valid_from: validFrom.toISOString(),
    ...overrides
  }
}

beforeEach(() => {
  vi.clearAllMocks()
  mockCheckServerIdentity.mockReturnValue(undefined)
})

describe('scanSSL', () => {
  it('returns score 100 for valid cert with TLS 1.3 and good issuer', async () => {
    const futureDate = new Date()
    futureDate.setFullYear(futureDate.getFullYear() + 1)
    const pastDate = new Date()
    pastDate.setFullYear(pastDate.getFullYear() - 1)

    setupConnect({
      issuer: { O: 'Let\'s Encrypt', CN: 'R3' },
      subject: { O: 'My Company', CN: 'example.com' },
      valid_to: futureDate.toISOString(),
      valid_from: pastDate.toISOString()
    }, 'TLSv1.3')

    const result = await scanSSL('example.com')

    expect(result.name).toBe('SSL/TLS')
    expect(result.score).toBe(100)
    expect(result.findings).toHaveLength(0)
    expect(result.info).toContain('Protocol: TLSv1.3')
    expect(result.info?.some(i => i.includes('Let\'s Encrypt'))).toBe(true)
  })

  it('returns critical finding and low score for expired cert', async () => {
    const pastDate = new Date()
    pastDate.setFullYear(pastDate.getFullYear() - 1)
    const olderDate = new Date()
    olderDate.setFullYear(olderDate.getFullYear() - 2)

    setupConnect({
      issuer: { O: 'Let\'s Encrypt', CN: 'R3' },
      subject: { O: 'My Company', CN: 'example.com' },
      valid_to: pastDate.toISOString(),
      valid_from: olderDate.toISOString()
    }, 'TLSv1.3')

    const result = await scanSSL('example.com')

    expect(result.score).toBeLessThanOrEqual(60)
    expect(result.findings.some(f => f.severity === 'critical' && f.title.includes('expired'))).toBe(true)
  })

  it('returns score 0 on connection failure', async () => {
    setupConnectError('ECONNREFUSED')

    const result = await scanSSL('unreachable.example.com')

    expect(result.name).toBe('SSL/TLS')
    expect(result.score).toBe(0)
    expect(result.findings).toHaveLength(1)
    expect(result.findings[0].severity).toBe('critical')
    expect(result.findings[0].title).toBe('SSL connection failed')
  })

  it('returns medium warning for cert expiring within 30 days', async () => {
    const soonDate = new Date()
    soonDate.setDate(soonDate.getDate() + 15)
    const pastDate = new Date()
    pastDate.setFullYear(pastDate.getFullYear() - 1)

    setupConnect({
      issuer: { O: 'Let\'s Encrypt', CN: 'R3' },
      subject: { O: 'My Company', CN: 'example.com' },
      valid_to: soonDate.toISOString(),
      valid_from: pastDate.toISOString()
    }, 'TLSv1.2')

    const result = await scanSSL('example.com')

    expect(result.score).toBe(90)
    expect(result.findings).toHaveLength(1)
    expect(result.findings[0].severity).toBe('medium')
    expect(result.findings[0].title).toContain('expiring soon')
  })

  it('scores an expired certificate as 0', async () => {
    const pastDate = new Date()
    pastDate.setDate(pastDate.getDate() - 10)

    setupConnect(validCert({ valid_to: pastDate.toISOString() }), 'TLSv1.3', {
      authorized: false,
      authorizationError: 'CERT_HAS_EXPIRED'
    })

    const result = await scanSSL('example.com')

    expect(result.score).toBe(0)
    expect(result.findings).toHaveLength(1)
    expect(result.findings[0].title).toBe('SSL certificate expired')
  })

  it('flags a certificate that is not valid yet', async () => {
    const futureStart = new Date()
    futureStart.setDate(futureStart.getDate() + 10)

    setupConnect(validCert({ valid_from: futureStart.toISOString() }), 'TLSv1.3')

    const result = await scanSSL('example.com')

    expect(result.score).toBe(0)
    expect(result.findings[0].title).toBe('SSL certificate not valid yet')
  })

  it('flags a certificate issued for another hostname', async () => {
    mockCheckServerIdentity.mockReturnValue(new Error('Hostname does not match the certificate altnames'))
    setupConnect(validCert(), 'TLSv1.3', { authorized: false, authorizationError: 'ERR_TLS_CERT_ALTNAME_INVALID' })

    const result = await scanSSL('wrong.example.com')

    expect(result.score).toBe(0)
    expect(result.findings).toHaveLength(1)
    expect(result.findings[0].severity).toBe('critical')
    expect(result.findings[0].title).toBe('Certificate does not match the hostname')
    expect(mockCheckServerIdentity).toHaveBeenCalledWith('wrong.example.com', expect.anything())
  })

  it('scores a self-signed certificate as 0', async () => {
    setupConnect(
      validCert({ issuer: { O: 'Acme', CN: 'example.com' }, subject: { O: 'Acme', CN: 'example.com' } }),
      'TLSv1.3',
      { authorized: false, authorizationError: 'DEPTH_ZERO_SELF_SIGNED_CERT' }
    )

    const result = await scanSSL('example.com')

    expect(result.score).toBe(0)
    expect(result.findings).toHaveLength(1)
    expect(result.findings[0].title).toBe('Self-signed certificate')
  })

  it('flags a certificate from an untrusted authority', async () => {
    setupConnect(validCert(), 'TLSv1.3', { authorized: false, authorizationError: 'SELF_SIGNED_CERT_IN_CHAIN' })

    const result = await scanSSL('example.com')

    expect(result.score).toBe(0)
    expect(result.findings[0].severity).toBe('critical')
    expect(result.findings[0].title).toBe('Certificate issued by an untrusted authority')
  })

  it('deducts for an incomplete chain without failing the check', async () => {
    setupConnect(validCert(), 'TLSv1.3', { authorized: false, authorizationError: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' })

    const result = await scanSSL('example.com')

    expect(result.score).toBe(70)
    expect(result.findings).toHaveLength(1)
    expect(result.findings[0].severity).toBe('high')
    expect(result.findings[0].title).toBe('Incomplete certificate chain')
  })

  it('keeps a trusted certificate at 100 when the chain verified', async () => {
    setupConnect(validCert(), 'TLSv1.3', { authorized: true })

    const result = await scanSSL('example.com')

    expect(result.score).toBe(100)
    expect(result.findings).toHaveLength(0)
  })

  it('connects to the given port and omits SNI for an IP address', async () => {
    setupConnect(validCert(), 'TLSv1.3', { authorized: true })

    await scanSSL('example.com', 8443)
    expect(mockConnect.mock.calls[0][0]).toBe(8443)
    expect(mockConnect.mock.calls[0][2]).toMatchObject({ servername: 'example.com' })

    await scanSSL('192.0.2.10')
    expect(mockConnect.mock.calls[1][0]).toBe(443)
    expect(mockConnect.mock.calls[1][2]).not.toHaveProperty('servername')
  })
})
