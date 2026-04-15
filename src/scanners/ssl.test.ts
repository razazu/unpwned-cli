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
      connect: vi.fn()
    }
  }
})

import tls from 'node:tls'

const mockConnect = vi.mocked(tls.connect)

function setupConnect(cert: Record<string, unknown>, protocol: string) {
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
      getProtocol: vi.fn(() => protocol)
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

beforeEach(() => {
  vi.clearAllMocks()
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
})
