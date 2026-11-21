import { existsSync, mkdtempSync, rmSync } from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { disableTelemetry, isFirstRun, showFirstRunNotice } from './telemetry.js'

vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>()
  return { ...actual, homedir: vi.fn(actual.homedir) }
})

describe('showFirstRunNotice', () => {
  let home: string

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'unpwned-test-'))
    vi.mocked(homedir).mockReturnValue(home)
    vi.stubEnv('DO_NOT_TRACK', '')
    vi.stubEnv('UNPWNED_TELEMETRY', '')
  })

  afterEach(() => {
    vi.unstubAllEnvs()
    vi.restoreAllMocks()
    rmSync(home, { recursive: true, force: true })
  })

  it('shows the notice on the first run', () => {
    const write = vi.fn()

    expect(showFirstRunNotice(true, write)).toBe(true)
    expect(write).toHaveBeenCalledOnce()
    expect(write.mock.calls[0][0]).toContain('Anonymous telemetry is enabled')
  })

  it('shows the notice only once', () => {
    const write = vi.fn()

    showFirstRunNotice(true, write)

    expect(isFirstRun()).toBe(false)
    expect(existsSync(join(home, '.unpwned', 'config.json'))).toBe(true)
    expect(showFirstRunNotice(true, write)).toBe(false)
    expect(write).toHaveBeenCalledOnce()
  })

  it('stays silent when telemetry is turned off for the scan', () => {
    const write = vi.fn()

    expect(showFirstRunNotice(false, write)).toBe(false)
    expect(write).not.toHaveBeenCalled()
    expect(isFirstRun()).toBe(true)
  })

  it('stays silent when DO_NOT_TRACK is set', () => {
    vi.stubEnv('DO_NOT_TRACK', '1')
    const write = vi.fn()

    expect(showFirstRunNotice(true, write)).toBe(false)
    expect(write).not.toHaveBeenCalled()
  })

  it('stays silent after telemetry was disabled', () => {
    disableTelemetry()
    const write = vi.fn()

    expect(showFirstRunNotice(true, write)).toBe(false)
    expect(write).not.toHaveBeenCalled()
  })

  it('writes to stderr by default so stdout stays valid JSON', () => {
    const stderr = vi.spyOn(process.stderr, 'write').mockReturnValue(true)
    const stdout = vi.spyOn(process.stdout, 'write').mockReturnValue(true)

    showFirstRunNotice(true)

    expect(stderr).toHaveBeenCalledOnce()
    expect(stdout).not.toHaveBeenCalled()
  })
})
