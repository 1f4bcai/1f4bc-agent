import {
  chmod,
  link,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import {
  fromBase64,
  initIdentity,
  loadIdentity,
  normalizeBaseUrl,
  resolveIdentityPath,
  saveIdentity,
  toBase64,
  type AgentIdentity,
} from '../src/keys.js'

const walletPrivateKey = `0x${'11'.repeat(32)}`
const cleanup: string[] = []

async function temporaryDirectory(prefix = '1f4bc-keys-security-'): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), prefix))
  cleanup.push(directory)
  return directory
}

async function newIdentity(directory: string, name = 'identity.json'): Promise<AgentIdentity> {
  return initIdentity(join(directory, name), { walletPrivateKey })
}

afterEach(async () => {
  await Promise.all(cleanup.splice(0).map((directory) => rm(directory, {
    recursive: true,
    force: true,
  })))
})

describe('identity namespace validation', () => {
  it('accepts only an origin and returns its canonical origin', () => {
    expect(normalizeBaseUrl('https://EXAMPLE.com:443/')).toBe('https://example.com')
    expect(normalizeBaseUrl('http://localhost:8787/')).toBe('http://localhost:8787')

    for (const value of [
      'https://example.com/api',
      'https://example.com/?network=base',
      'https://example.com/#agent',
      'https://example.com?',
      'https://example.com#',
      'https://example.com/.',
    ]) {
      expect(() => normalizeBaseUrl(value), value).toThrow(/origin|path|query|fragment/i)
    }
  })

  it('accepts only canonical RFC 4648 base64', () => {
    const canonical = toBase64(new Uint8Array(32))
    expect(fromBase64(canonical)).toEqual(new Uint8Array(32))

    const aliases = [
      canonical.replace(/=$/, ''),
      `${canonical.slice(0, 4)}\n${canonical.slice(4)}`,
      `${canonical.slice(0, -2)}B=`,
    ]
    for (const alias of aliases) {
      expect(() => fromBase64(alias), alias).toThrow(/canonical base64/i)
    }
  })
})

describe('identity cryptographic validation', () => {
  it('derives the Ed25519 public key and rejects a mismatched stored key', async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, 'identity.json')
    await newIdentity(directory)
    const stored = JSON.parse(await readFile(path, 'utf8')) as AgentIdentity
    stored.publicKey = toBase64(new Uint8Array(32))
    await writeFile(path, `${JSON.stringify(stored)}\n`, { mode: 0o600 })

    await expect(loadIdentity(path)).rejects.toThrow(/public key.*private key/i)
  })

  it('rejects an invalid wallet scalar without exposing curve internals', async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, 'identity.json')
    const invalidScalar = `0x${'00'.repeat(32)}`

    await expect(initIdentity(path, {
      walletPrivateKey: invalidScalar,
    })).rejects.toThrow(/^wallet private key is invalid$/)

    await newIdentity(directory)
    const stored = JSON.parse(await readFile(path, 'utf8')) as AgentIdentity
    stored.walletPrivateKey = invalidScalar as `0x${string}`
    await writeFile(path, `${JSON.stringify(stored)}\n`, { mode: 0o600 })
    await expect(loadIdentity(path)).rejects.toThrow(/^wallet private key is invalid$/)
  })

  it('validates before overwriting and preserves the prior identity on failure', async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, 'identity.json')
    const original = await newIdentity(directory)
    const invalid = { ...original, publicKey: toBase64(new Uint8Array(32)) }

    await expect(saveIdentity(path, invalid, { overwrite: true }))
      .rejects.toThrow(/public key.*private key/i)
    await expect(loadIdentity(path)).resolves.toEqual(original)
  })
})

describe('identity file custody', () => {
  it('rejects identity symlinks and non-regular files', async () => {
    const directory = await temporaryDirectory()
    const target = join(directory, 'identity.json')
    const alias = join(directory, 'identity-alias.json')
    await newIdentity(directory)
    await symlink(target, alias)

    await expect(loadIdentity(alias)).rejects.toThrow(/symbolic link/i)

    const notAFile = join(directory, 'identity-directory')
    await mkdir(notAFile)
    await expect(loadIdentity(notAFile)).rejects.toThrow(/regular file/i)

    const aliasDirectory = join(directory, 'identity-directory-alias')
    await symlink(directory, aliasDirectory)
    await expect(loadIdentity(join(aliasDirectory, 'identity.json')))
      .rejects.toThrow(/directory.*symbolic link/i)
  })

  it.runIf(process.platform !== 'win32')(
    'rejects identity files readable or writable by another Unix user',
    async () => {
      const directory = await temporaryDirectory()
      const path = join(directory, 'identity.json')
      await newIdentity(directory)
      await chmod(path, 0o644)

      await expect(loadIdentity(path)).rejects.toThrow(/permissions/i)
    },
  )

  it('rejects hard-linked identity files that could retain another key copy', async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, 'identity.json')
    const alias = join(directory, 'identity-hard-link.json')
    await newIdentity(directory)
    await link(path, alias)

    await expect(loadIdentity(path)).rejects.toThrow(/unsafe link count/i)
    await expect(loadIdentity(alias)).rejects.toThrow(/unsafe link count/i)
  })

  it('uses atomic no-clobber creation under concurrent writers', async () => {
    const directory = await temporaryDirectory()
    const firstDirectory = await temporaryDirectory()
    const secondDirectory = await temporaryDirectory()
    const first = await newIdentity(firstDirectory)
    const second = await newIdentity(secondDirectory)
    const target = join(directory, 'identity.json')

    const results = await Promise.allSettled([
      saveIdentity(target, first),
      saveIdentity(target, second),
    ])
    expect(results.filter(({ status }) => status === 'fulfilled')).toHaveLength(1)
    expect(results.filter(({ status }) => status === 'rejected')).toHaveLength(1)
    expect([first, second]).toContainEqual(await loadIdentity(target))
    expect((await readdir(directory)).filter((entry) => entry.includes('.tmp-'))).toEqual([])
  })

  it('rejects unsafe overwrite targets and always cleans temporary files', async () => {
    const directory = await temporaryDirectory()
    const sourceDirectory = await temporaryDirectory()
    const identity = await newIdentity(sourceDirectory)
    const target = join(directory, 'identity.json')
    await mkdir(target)

    await expect(saveIdentity(target, identity, { overwrite: true }))
      .rejects.toThrow(/regular file/i)
    expect((await readdir(directory)).filter((entry) => entry.includes('.tmp-'))).toEqual([])

    await rm(target, { recursive: true })
    const victim = join(directory, 'victim.json')
    await writeFile(victim, 'do not replace\n', { mode: 0o600 })
    await symlink(victim, target)
    await expect(saveIdentity(target, identity, { overwrite: true }))
      .rejects.toThrow(/symbolic link/i)
    expect(await readFile(victim, 'utf8')).toBe('do not replace\n')
    expect((await readdir(directory)).filter((entry) => entry.includes('.tmp-'))).toEqual([])
  })
})

describe('legacy identity migration', () => {
  it.runIf(process.platform !== 'win32')(
    'recursively hardens copied secret directories and files',
    async () => {
      const home = await temporaryDirectory('1f4bc-legacy-security-')
      const legacyDirectory = join(home, '.agent-bazaar')
      await newIdentity(legacyDirectory)
      const nestedDirectory = join(legacyDirectory, 'payment-attempts', 'agent')
      const nestedFile = join(nestedDirectory, 'pending.json')
      await mkdir(nestedDirectory, { recursive: true, mode: 0o777 })
      await writeFile(nestedFile, '{"secret":true}\n', { mode: 0o666 })
      await chmod(join(legacyDirectory, 'payment-attempts'), 0o777)
      await chmod(nestedDirectory, 0o777)
      await chmod(nestedFile, 0o666)

      const resolved = await resolveIdentityPath(undefined, home, {})
      const migratedDirectory = dirname(resolved)
      expect((await lstat(migratedDirectory)).mode & 0o777).toBe(0o700)
      expect((await lstat(join(migratedDirectory, 'payment-attempts'))).mode & 0o777)
        .toBe(0o700)
      expect((await lstat(join(migratedDirectory, 'payment-attempts', 'agent'))).mode & 0o777)
        .toBe(0o700)
      expect((await lstat(join(migratedDirectory, 'payment-attempts', 'agent', 'pending.json'))).mode & 0o777)
        .toBe(0o600)
      await expect(lstat(legacyDirectory)).rejects.toMatchObject({ code: 'ENOENT' })
    },
  )

  it('never follows a symlink found in the legacy secret tree', async () => {
    const home = await temporaryDirectory('1f4bc-legacy-symlink-')
    const legacyDirectory = join(home, '.agent-bazaar')
    await newIdentity(legacyDirectory)
    const external = join(home, 'external-secret.json')
    await writeFile(external, '{"untouched":true}\n', { mode: 0o644 })
    await symlink(external, join(legacyDirectory, 'linked-secret.json'))
    const externalMode = (await lstat(external)).mode & 0o777

    await expect(resolveIdentityPath(undefined, home, {})).rejects.toThrow(/symbolic link/i)
    expect(await readFile(external, 'utf8')).toBe('{"untouched":true}\n')
    expect((await lstat(external)).mode & 0o777).toBe(externalMode)
    await expect(lstat(join(home, '.1f4bc'))).rejects.toMatchObject({ code: 'ENOENT' })
  })
})
