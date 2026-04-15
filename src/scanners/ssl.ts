import tls from 'node:tls'
import type { ScanResult } from '../types.js'

export async function scanSSL(hostname: string): Promise<ScanResult> {
  const findings: ScanResult['findings'] = []
  const info: string[] = []
  let score = 100

  try {
    const { socket, cert, protocol } = await connectTLS(hostname)
    socket.destroy()

    const issuer = cert.issuer?.O || cert.issuer?.CN || 'Unknown'
    const validTo = new Date(cert.valid_to)
    const validFrom = new Date(cert.valid_from)
    const now = new Date()
    const daysUntilExpiry = Math.floor((validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24))

    info.push(`Issuer: ${issuer}`)
    info.push(`Expires: ${validTo.toISOString().split('T')[0]}`)
    info.push(`Protocol: ${protocol}`)

    if (validTo < now) {
      findings.push({
        severity: 'critical',
        title: 'SSL certificate expired',
        description: `Certificate expired on ${validTo.toISOString().split('T')[0]}`
      })
      score -= 40
    } else if (daysUntilExpiry <= 30) {
      findings.push({
        severity: 'medium',
        title: 'SSL certificate expiring soon',
        description: `Certificate expires in ${daysUntilExpiry} days (${validTo.toISOString().split('T')[0]})`
      })
      score -= 10
    }

    const tlsVersion = protocol || ''
    if (tlsVersion === 'TLSv1.3' || tlsVersion === 'TLSv1.2') {
      // full points
    } else {
      findings.push({
        severity: 'high',
        title: 'Outdated TLS protocol version',
        description: `Server uses ${tlsVersion || 'unknown protocol'}, which is insecure. TLS 1.2+ is required.`
      })
      score -= 30
    }

    const isSelfSigned = cert.issuer?.CN === cert.subject?.CN
      && cert.issuer?.O === cert.subject?.O
    if (isSelfSigned) {
      findings.push({
        severity: 'high',
        title: 'Self-signed certificate',
        description: 'Certificate is self-signed and will not be trusted by browsers.'
      })
      score -= 30
    }

    return { name: 'SSL/TLS', score: Math.max(0, score), findings, info }
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
}

function connectTLS(hostname: string): Promise<TLSResult> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(443, hostname, {
      servername: hostname,
      timeout: 10000,
      rejectUnauthorized: false
    }, () => {
      const cert = socket.getPeerCertificate()
      const protocol = socket.getProtocol() || 'unknown'
      resolve({ socket, cert, protocol })
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
