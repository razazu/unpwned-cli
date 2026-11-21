import { isIP } from 'node:net'
import tls from 'node:tls'
import type { ScanResult } from '../types.js'

const UNTRUSTED_ROOT_CODES = new Set(['SELF_SIGNED_CERT_IN_CHAIN', 'CERT_UNTRUSTED', 'CERT_REJECTED', 'CERT_REVOKED'])

const INCOMPLETE_CHAIN_CODES = new Set([
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
  'UNABLE_TO_GET_ISSUER_CERT',
])

function errorCode(error: unknown): string {
  if (typeof error === 'string') return error
  if (error && typeof error === 'object') {
    const { code, message } = error as { code?: unknown; message?: unknown }
    if (typeof code === 'string') return code
    if (typeof message === 'string') return message
  }
  return ''
}

export async function scanSSL(hostname: string, port = 443): Promise<ScanResult> {
  const findings: ScanResult['findings'] = []
  const info: string[] = []
  let score = 100
  let trusted = true

  try {
    const { socket, cert, protocol, authorized, authorizationError } = await connectTLS(hostname, port)
    socket.destroy()

    const issuer = cert.issuer?.O || cert.issuer?.CN || 'Unknown'
    const validTo = new Date(cert.valid_to)
    const validFrom = new Date(cert.valid_from)
    const now = new Date()
    const daysUntilExpiry = Math.floor((validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24))
    const chainError = authorized === false ? errorCode(authorizationError) : ''

    info.push(`Issuer: ${issuer}`)
    info.push(`Expires: ${validTo.toISOString().split('T')[0]}`)
    info.push(`Protocol: ${protocol}`)

    if (validTo < now) {
      findings.push({
        severity: 'critical',
        title: 'SSL certificate expired',
        description: `Certificate expired on ${validTo.toISOString().split('T')[0]}`
      })
      trusted = false
    } else if (validFrom > now) {
      findings.push({
        severity: 'critical',
        title: 'SSL certificate not valid yet',
        description: `Certificate becomes valid on ${validFrom.toISOString().split('T')[0]}`
      })
      trusted = false
    } else if (daysUntilExpiry <= 30) {
      findings.push({
        severity: 'medium',
        title: 'SSL certificate expiring soon',
        description: `Certificate expires in ${daysUntilExpiry} days (${validTo.toISOString().split('T')[0]})`
      })
      score -= 10
    }

    const identityError = tls.checkServerIdentity(hostname, cert)
    if (identityError) {
      findings.push({
        severity: 'critical',
        title: 'Certificate does not match the hostname',
        description: `The certificate is not valid for ${hostname}. Browsers will refuse the connection.`
      })
      trusted = false
    }

    const tlsVersion = protocol || ''
    if (tlsVersion !== 'TLSv1.3' && tlsVersion !== 'TLSv1.2') {
      findings.push({
        severity: 'high',
        title: 'Outdated TLS protocol version',
        description: `Server uses ${tlsVersion || 'unknown protocol'}, which is insecure. TLS 1.2+ is required.`
      })
      score -= 30
    }

    const isSelfSigned =
      chainError === 'DEPTH_ZERO_SELF_SIGNED_CERT' ||
      (cert.issuer?.CN === cert.subject?.CN && cert.issuer?.O === cert.subject?.O)

    if (isSelfSigned) {
      findings.push({
        severity: 'critical',
        title: 'Self-signed certificate',
        description: 'Certificate is self-signed and will not be trusted by browsers.'
      })
      trusted = false
    } else if (UNTRUSTED_ROOT_CODES.has(chainError)) {
      findings.push({
        severity: 'critical',
        title: 'Certificate issued by an untrusted authority',
        description: 'The certificate chain ends in an authority that browsers do not trust.'
      })
      trusted = false
    } else if (INCOMPLETE_CHAIN_CODES.has(chainError)) {
      findings.push({
        severity: 'high',
        title: 'Incomplete certificate chain',
        description:
          'The server does not send the intermediate certificates needed to verify its certificate. Some clients will refuse the connection.'
      })
      score -= 30
    }

    return { name: 'SSL/TLS', score: trusted ? Math.max(0, score) : 0, findings, info }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    return {
      name: 'SSL/TLS',
      score: 0,
      findings: [{
        severity: 'critical',
        title: 'SSL connection failed',
        description: `Could not establish TLS connection: ${message}`
      }],
      info: []
    }
  }
}

interface TLSResult {
  socket: tls.TLSSocket
  cert: tls.PeerCertificate
  protocol: string
  authorized: boolean | undefined
  authorizationError: unknown
}

function connectTLS(hostname: string, port: number): Promise<TLSResult> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(port, hostname, {
      ...(isIP(hostname) ? {} : { servername: hostname }),
      timeout: 10000,
      rejectUnauthorized: false
    }, () => {
      const cert = socket.getPeerCertificate()
      const protocol = socket.getProtocol() || 'unknown'
      resolve({
        socket,
        cert,
        protocol,
        authorized: socket.authorized,
        authorizationError: socket.authorizationError,
      })
    })

    socket.on('error', (err) => {
      socket.destroy()
      reject(err)
    })

    socket.on('timeout', () => {
      socket.destroy()
      reject(new Error('Connection timed out'))
    })
  })
}
