import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { withFileLock } from '../src/local-journal.js'

const cleanup: string[] = []

afterEach(async () => {
  await Promise.all(cleanup.splice(0).map((directory) => rm(directory, { recursive: true })))
})

describe('local journal locking', () => {
  it('never deletes a stale-looking lock or runs through it automatically', async () => {
    const directory = await mkdtemp(join(tmpdir(), '1f4bc-local-lock-'))
    cleanup.push(directory)
    const target = join(directory, 'journal.json')
    const lockPath = `${target}.lock`
    const staleContents = `${JSON.stringify({
      pid: Number.MAX_SAFE_INTEGER,
      token: 'old-owner',
      createdAt: 0,
    })}\n`
    await writeFile(lockPath, staleContents, { mode: 0o600 })
    const operation = vi.fn(async () => 'unsafe')

    await expect(withFileLock(target, operation, { waitMs: 0 }))
      .rejects.toThrow(/remove .*\.lock manually/i)
    expect(operation).not.toHaveBeenCalled()
    expect(await readFile(lockPath, 'utf8')).toBe(staleContents)
  })
})
