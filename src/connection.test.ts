import { describe, expect, it } from 'vitest'
import { describeConnectionFailure, isTransientFailure } from './connection.js'

function fetchFailure(code: string): TypeError {
  return new TypeError('fetch failed', { cause: Object.assign(new Error(code), { code }) })
}

function timeout(): DOMException {
  return new DOMException('The operation was aborted due to timeout', 'TimeoutError')
}

describe('describeConnectionFailure', () => {
  it.each([
    ['ECONNREFUSED', 'the connection was refused'],
    ['ECONNRESET', 'the connection was reset'],
    ['UND_ERR_SOCKET', 'the connection was closed'],
    ['UND_ERR_CONNECT_TIMEOUT', 'the connection timed out'],
    ['CERT_HAS_EXPIRED', 'the certificate has expired'],
    ['ERR_TLS_CERT_ALTNAME_INVALID', 'the certificate does not match the hostname'],
    ['DEPTH_ZERO_SELF_SIGNED_CERT', 'the certificate is self-signed'],
    ['SELF_SIGNED_CERT_IN_CHAIN', 'the certificate was issued by an untrusted authority'],
    ['UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'the certificate chain is incomplete'],
  ])('explains %s', (code, expected) => {
    expect(describeConnectionFailure(fetchFailure(code))).toBe(expected)
  })

  it('reads the code of the first error when several connection attempts failed', () => {
    const attempts = new AggregateError([Object.assign(new Error('refused'), { code: 'ECONNREFUSED' })])
    const failure = new TypeError('fetch failed', { cause: attempts })

    expect(describeConnectionFailure(failure)).toBe('the connection was refused')
  })

  it('explains a timeout', () => {
    expect(describeConnectionFailure(timeout())).toBe('no response within 10 seconds')
  })

  it('falls back to a generic reason for an unknown failure', () => {
    expect(describeConnectionFailure(new TypeError('fetch failed'))).toBe('the request failed')
    expect(describeConnectionFailure(fetchFailure('SOMETHING_NEW'))).toBe('the request failed')
    expect(describeConnectionFailure('boom')).toBe('the request failed')
  })
})

describe('isTransientFailure', () => {
  it('treats a reset connection and an unknown failure as transient', () => {
    expect(isTransientFailure(fetchFailure('ECONNRESET'))).toBe(true)
    expect(isTransientFailure(new TypeError('fetch failed'))).toBe(true)
  })

  it('does not treat a refused connection, a rejected certificate or a timeout as transient', () => {
    expect(isTransientFailure(fetchFailure('ECONNREFUSED'))).toBe(false)
    expect(isTransientFailure(fetchFailure('CERT_HAS_EXPIRED'))).toBe(false)
    expect(isTransientFailure(timeout())).toBe(false)
  })
})
