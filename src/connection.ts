export const PAGE_TIMEOUT_MS = 10000

const CERTIFICATE_FAILURES: Record<string, string> = {
  CERT_HAS_EXPIRED: 'the certificate has expired',
  CERT_NOT_YET_VALID: 'the certificate is not valid yet',
  ERR_TLS_CERT_ALTNAME_INVALID: 'the certificate does not match the hostname',
  DEPTH_ZERO_SELF_SIGNED_CERT: 'the certificate is self-signed',
  SELF_SIGNED_CERT_IN_CHAIN: 'the certificate was issued by an untrusted authority',
  CERT_UNTRUSTED: 'the certificate was issued by an untrusted authority',
  CERT_REJECTED: 'the certificate was rejected',
  CERT_REVOKED: 'the certificate has been revoked',
  UNABLE_TO_VERIFY_LEAF_SIGNATURE: 'the certificate chain is incomplete',
  UNABLE_TO_GET_ISSUER_CERT_LOCALLY: 'the certificate chain is incomplete',
  UNABLE_TO_GET_ISSUER_CERT: 'the certificate chain is incomplete',
}

const NETWORK_FAILURES: Record<string, string> = {
  ECONNREFUSED: 'the connection was refused',
  ECONNRESET: 'the connection was reset',
  UND_ERR_SOCKET: 'the connection was closed',
  EPIPE: 'the connection was closed',
  ETIMEDOUT: 'the connection timed out',
  UND_ERR_CONNECT_TIMEOUT: 'the connection timed out',
  EHOSTUNREACH: 'the host is unreachable',
  ENETUNREACH: 'the network is unreachable',
  ENOTFOUND: 'a host name did not resolve',
}

const TRANSIENT_CODES = new Set(['ECONNRESET', 'EPIPE', 'EAI_AGAIN', 'UND_ERR_SOCKET'])

const MAX_CAUSE_DEPTH = 5

function failureCode(error: unknown): string | null {
  let current: unknown = error
  for (let depth = 0; depth < MAX_CAUSE_DEPTH && current && typeof current === 'object'; depth++) {
    const { code, errors, cause } = current as { code?: unknown; errors?: unknown; cause?: unknown }
    if (typeof code === 'string') return code
    current = Array.isArray(errors) && errors.length > 0 ? errors[0] : cause
  }
  return null
}

function isTimeout(error: unknown): boolean {
  if (!error || typeof error !== 'object') return false
  const { name } = error as { name?: unknown }
  return name === 'TimeoutError' || name === 'AbortError'
}

export function isTransientFailure(error: unknown): boolean {
  if (isTimeout(error)) return false
  const code = failureCode(error)
  return code === null || TRANSIENT_CODES.has(code)
}

export function describeConnectionFailure(error: unknown): string {
  if (isTimeout(error)) return `no response within ${PAGE_TIMEOUT_MS / 1000} seconds`
  const code = failureCode(error)
  if (code === null) return 'the request failed'
  return CERTIFICATE_FAILURES[code] ?? NETWORK_FAILURES[code] ?? 'the request failed'
}
