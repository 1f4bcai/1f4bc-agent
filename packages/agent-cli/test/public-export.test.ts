import { execFile } from 'node:child_process'
import { deflateSync } from 'node:zlib'
import {
  chmod,
  link,
  mkdtemp,
  mkdir,
  readdir,
  readFile,
  realpath,
  rename,
  rm,
  stat,
  symlink,
  truncate,
  writeFile,
} from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { promisify } from 'node:util'
import { afterEach, expect, it } from 'vitest'
import { exportPublicSource } from '../scripts/export-public-source.mjs'
import { verifyPublicTree } from '../scripts/verify-public-tree.mjs'

const execFileAsync = promisify(execFile)
const cleanup: string[] = []
const CLEANUP_OPTIONS = Object.freeze({
  recursive: true,
  force: true,
  maxRetries: 10,
  retryDelay: 100,
})
const PUBLIC_GIT_NAME = '1F4BC Release'
const PUBLIC_GIT_EMAIL = 'support@1f4bc.com'
const PUBLIC_GIT_MESSAGE = 'release: publish @1f4bcai/agent@0.1.3'
const PUBLIC_GIT_DATE = '2026-08-25T00:00:00Z'

async function commitRelease(destination: string) {
  await execFileAsync('git', ['commit', '-m', PUBLIC_GIT_MESSAGE], {
    cwd: destination,
    env: {
      ...process.env,
      GIT_AUTHOR_DATE: PUBLIC_GIT_DATE,
      GIT_COMMITTER_DATE: PUBLIC_GIT_DATE,
    },
  })
}

async function installRawCommit(
  destination: string,
  label: string,
  metadataHeaders: string[],
  message = PUBLIC_GIT_MESSAGE,
) {
  const [{ stdout: tree }, { stdout: parent }] = await Promise.all([
    execFileAsync('git', ['rev-parse', 'HEAD^{tree}'], {
      cwd: destination,
      encoding: 'utf8',
    }),
    execFileAsync('git', ['rev-parse', 'HEAD'], {
      cwd: destination,
      encoding: 'utf8',
    }),
  ])
  const rawCommit = [
    `tree ${tree.trim()}`,
    `parent ${parent.trim()}`,
    ...metadataHeaders,
    '',
    message,
    '',
  ].join('\n')
  const rawCommitPath = join(dirname(destination), `${label}.txt`)
  await writeFile(rawCommitPath, rawCommit)
  const { stdout: commit } = await execFileAsync(
    'git', ['hash-object', '--literally', '-t', 'commit', '-w', rawCommitPath],
    { cwd: destination, encoding: 'utf8' },
  )
  await execFileAsync('git', ['update-ref', 'refs/heads/main', commit.trim()], {
    cwd: destination,
  })
  return commit.trim()
}

afterEach(async () => {
  for (const path of cleanup.splice(0)) await rm(path, CLEANUP_OPTIONS)
})

async function exportedRepository() {
  const parent = await mkdtemp(join(tmpdir(), '1f4bc-public-export-'))
  cleanup.push(parent)
  const destination = join(parent, 'public')
  await exportPublicSource(destination)
  await execFileAsync('git', ['init', '-b', 'main'], { cwd: destination })
  await execFileAsync('git', ['config', 'maintenance.auto', 'false'], { cwd: destination })
  await execFileAsync('git', ['config', 'gc.auto', '0'], { cwd: destination })
  await execFileAsync('git', ['config', 'user.name', PUBLIC_GIT_NAME], { cwd: destination })
  await execFileAsync('git', ['config', 'user.email', PUBLIC_GIT_EMAIL], { cwd: destination })
  await execFileAsync('git', ['add', '--all'], { cwd: destination })
  await commitRelease(destination)
  return destination
}

it('exports only a fresh-history minimal CLI source and locked dependency closure', async () => {
  const destination = await exportedRepository()
  const result = await verifyPublicTree(destination)
  expect(result.trackedFiles).toBeGreaterThan(30)
  expect(result.lockedPackages).toBeGreaterThan(50)
  expect(result.lockedPackages).toBeLessThan(180)
  expect(JSON.parse(await readFile(join(destination, 'package.json'), 'utf8'))).toEqual({
    name: '1f4bc-agent-release-source',
    version: '0.1.3',
    private: true,
    type: 'module',
    workspaces: ['packages/agent-cli'],
  })
  await expect(readFile(join(destination, 'wrangler.toml'), 'utf8')).rejects.toMatchObject({
    code: 'ENOENT',
  })
}, 20_000)

it('disables background Git maintenance in disposable export repositories', async () => {
  const destination = await exportedRepository()
  const [{ stdout: maintenanceAuto }, { stdout: gcAuto }] = await Promise.all([
    execFileAsync('git', ['config', '--get', 'maintenance.auto'], {
      cwd: destination,
      encoding: 'utf8',
    }),
    execFileAsync('git', ['config', '--get', 'gc.auto'], {
      cwd: destination,
      encoding: 'utf8',
    }),
  ])
  expect(maintenanceAuto.trim()).toBe('false')
  expect(gcAuto.trim()).toBe('0')
})

it('accepts the exact canonical Actions checkout-style local configuration', async () => {
  const destination = await exportedRepository()
  await execFileAsync(
    'git', ['remote', 'add', 'origin', 'https://github.com/1f4bcai/1f4bc-agent'],
    { cwd: destination },
  )
  await execFileAsync('git', ['update-ref', 'refs/remotes/origin/main', 'HEAD'], {
    cwd: destination,
  })
  await execFileAsync('git', ['branch', '--set-upstream-to=origin/main', 'main'], {
    cwd: destination,
  })
  await expect(verifyPublicTree(destination)).resolves.toMatchObject({
    trackedFiles: expect.any(Number),
  })
})

it('requires the replacement history root to be exactly version 0.1.3', async () => {
  const destination = await exportedRepository()
  const versionedPaths = [
    'package.json',
    'packages/agent-cli/package.json',
    'package-lock.json',
  ]
  const originals = new Map(
    await Promise.all(versionedPaths.map(async (path) => [
      path,
      await readFile(join(destination, path), 'utf8'),
    ] as const)),
  )

  await rm(join(destination, '.git'), CLEANUP_OPTIONS)
  for (const path of versionedPaths) {
    const document = JSON.parse(originals.get(path)!)
    document.version = '0.1.4'
    if (path === 'package-lock.json') {
      document.packages[''].version = '0.1.4'
      document.packages['packages/agent-cli'].version = '0.1.4'
    }
    await writeFile(join(destination, path), `${JSON.stringify(document, null, 2)}\n`)
  }

  await execFileAsync('git', ['init', '-b', 'main'], { cwd: destination })
  await execFileAsync('git', ['config', 'maintenance.auto', 'false'], { cwd: destination })
  await execFileAsync('git', ['config', 'gc.auto', '0'], { cwd: destination })
  await execFileAsync('git', ['config', 'user.name', PUBLIC_GIT_NAME], { cwd: destination })
  await execFileAsync('git', ['config', 'user.email', PUBLIC_GIT_EMAIL], { cwd: destination })
  await execFileAsync('git', ['add', '--all'], { cwd: destination })
  await execFileAsync(
    'git', ['commit', '-m', 'release: publish @1f4bcai/agent@0.1.4'],
    {
      cwd: destination,
      env: {
        ...process.env,
        GIT_AUTHOR_DATE: PUBLIC_GIT_DATE,
        GIT_COMMITTER_DATE: PUBLIC_GIT_DATE,
      },
    },
  )

  for (const [path, contents] of originals) {
    await writeFile(join(destination, path), contents)
  }
  await execFileAsync('git', ['add', '--all'], { cwd: destination })
  await commitRelease(destination)

  await expect(verifyPublicTree(destination)).rejects.toThrow(
    /replacement history root.*0\.1\.3/i,
  )
}, 20_000)

it('rejects two canonical commits that claim the same package version', async () => {
  const destination = await exportedRepository()
  await execFileAsync('git', ['commit', '--allow-empty', '-m', PUBLIC_GIT_MESSAGE], {
    cwd: destination,
    env: {
      ...process.env,
      GIT_AUTHOR_DATE: '2026-08-25T00:01:00Z',
      GIT_COMMITTER_DATE: '2026-08-25T00:01:00Z',
    },
  })
  await expect(verifyPublicTree(destination)).rejects.toThrow(
    /package versions must increase strictly/i,
  )
})

it('requires the current root, package, and lock versions to agree', async () => {
  const destination = await exportedRepository()
  const packagePath = join(destination, 'packages', 'agent-cli', 'package.json')
  const manifest = JSON.parse(await readFile(packagePath, 'utf8'))
  manifest.version = '9.9.9'
  await writeFile(packagePath, `${JSON.stringify(manifest, null, 2)}\n`)
  await execFileAsync('git', ['add', 'packages/agent-cli/package.json'], {
    cwd: destination,
  })
  await execFileAsync('git', ['commit', '-m', 'release: publish @1f4bcai/agent@9.9.9'], {
    cwd: destination,
    env: {
      ...process.env,
      GIT_AUTHOR_DATE: '2026-08-25T00:01:00Z',
      GIT_COMMITTER_DATE: '2026-08-25T00:01:00Z',
    },
  })
  await expect(
    verifyPublicTree(destination, { mode: 'snapshot-only' }),
  ).rejects.toThrow(/root, package, and lock versions must agree/i)
  await expect(verifyPublicTree(destination)).rejects.toThrow(
    /root, package, and lock versions must agree/i,
  )
})

it('rejects a disallowed file anywhere in public Git history', async () => {
  const destination = await exportedRepository()
  const injectedPath = 'private-monorepo.txt'
  await writeFile(join(destination, injectedPath), 'must never leave\n')
  await execFileAsync('git', ['add', injectedPath], { cwd: destination })
  await commitRelease(destination)
  await execFileAsync('git', ['rm', injectedPath], { cwd: destination })
  await commitRelease(destination)
  const error = await verifyPublicTree(destination).then(
    () => null,
    (reason: unknown) => reason,
  )
  expect(error).toBeInstanceOf(Error)
  expect((error as Error).message).toMatch(/history contains disallowed path/i)
  expect((error as Error).message).not.toContain(injectedPath)
})

it('rejects a credential added and deleted under an otherwise allowed historical path', async () => {
  const destination = await exportedRepository()
  const leakedPath = join(destination, 'packages/agent-cli/README.md')
  const original = await readFile(leakedPath, 'utf8')
  const credential = ['sk', 'A'.repeat(40)].join('-')
  await writeFile(leakedPath, `credential=${credential}\n`)
  await execFileAsync('git', ['add', 'packages/agent-cli/README.md'], {
    cwd: destination,
  })
  await commitRelease(destination)
  await expect(verifyPublicTree(destination, { mode: 'snapshot-only' })).rejects.toThrow(
    /public tree contains a credential/i,
  )
  await writeFile(leakedPath, original)
  await execFileAsync('git', ['add', 'packages/agent-cli/README.md'], {
    cwd: destination,
  })
  await commitRelease(destination)
  await expect(verifyPublicTree(destination)).rejects.toThrow(/history contains a credential/i)
})

it('rejects unknown verification modes instead of falling back to snapshot-only', async () => {
  await expect(
    verifyPublicTree('/not-read', { mode: 'unknown' as never }),
  ).rejects.toThrow(/mode must be full or snapshot-only/i)
})

it('rejects binary text hidden in an allowed historical path', async () => {
  const destination = await exportedRepository()
  const relative = 'packages/agent-cli/README.md'
  const path = join(destination, relative)
  const original = await readFile(path)
  await writeFile(path, Buffer.from([0x66, 0x6f, 0x00, 0x80]))
  await execFileAsync('git', ['add', relative], { cwd: destination })
  await commitRelease(destination)
  await writeFile(path, original)
  await execFileAsync('git', ['add', relative], { cwd: destination })
  await commitRelease(destination)
  await expect(verifyPublicTree(destination)).rejects.toThrow(/binary NUL|UTF-8/i)
})

it('rejects malformed UTF-8 hidden in an allowed historical path without a NUL byte', async () => {
  const destination = await exportedRepository()
  const relative = 'packages/agent-cli/README.md'
  const path = join(destination, relative)
  const original = await readFile(path)
  await writeFile(path, Buffer.from([0x66, 0x6f, 0xff, 0xfe, 0xfd]))
  await execFileAsync('git', ['add', relative], { cwd: destination })
  await commitRelease(destination)
  await writeFile(path, original)
  await execFileAsync('git', ['add', relative], { cwd: destination })
  await commitRelease(destination)
  await expect(verifyPublicTree(destination)).rejects.toThrow(/not valid UTF-8/i)
})

it('refuses an uncommitted safe copy that masks an unsafe committed release workflow', async () => {
  const destination = await exportedRepository()
  const relative = '.github/workflows/release-agent-cli.yml'
  const path = join(destination, relative)
  const safe = await readFile(path, 'utf8')
  await writeFile(path, `${safe}\n# run: npm publish\n`)
  await execFileAsync('git', ['add', relative], { cwd: destination })
  await commitRelease(destination)
  await expect(verifyPublicTree(destination, { mode: 'snapshot-only' })).rejects.toThrow(
    /direct npm publish/i,
  )
  await writeFile(path, safe)
  await expect(verifyPublicTree(destination)).rejects.toThrow(
    /blob object ID.*index|worktree file bytes.*index blob/i,
  )
})

it('rejects Git replacement refs instead of letting them hide unsafe history', async () => {
  const destination = await exportedRepository()
  const relative = 'packages/agent-cli/README.md'
  const path = join(destination, relative)
  const original = await readFile(path, 'utf8')
  const { stdout: safeCommit } = await execFileAsync('git', ['rev-parse', 'HEAD'], {
    cwd: destination,
    encoding: 'utf8',
  })
  const credential = ['npm', 'r'.repeat(36)].join('_')
  await writeFile(path, `unsafe history ${credential}\n`)
  await execFileAsync('git', ['add', relative], { cwd: destination })
  await commitRelease(destination)
  const { stdout: unsafeCommit } = await execFileAsync('git', ['rev-parse', 'HEAD'], {
    cwd: destination,
    encoding: 'utf8',
  })
  await writeFile(path, original)
  await execFileAsync('git', ['add', relative], { cwd: destination })
  await commitRelease(destination)
  await execFileAsync('git', ['replace', unsafeCommit.trim(), safeCommit.trim()], {
    cwd: destination,
  })
  await expect(verifyPublicTree(destination)).rejects.toThrow(/replace refs/i)
})

it('rejects externally linked Git metadata and object storage', async () => {
  const linkedGit = await exportedRepository()
  const linkedGitDirectory = join(dirname(linkedGit), 'external-git-metadata')
  await rename(join(linkedGit, '.git'), linkedGitDirectory)
  await symlink(linkedGitDirectory, join(linkedGit, '.git'))
  await expect(verifyPublicTree(linkedGit)).rejects.toThrow(/\.git.*real local directory/i)

  const linkedObjects = await exportedRepository()
  const linkedObjectsDirectory = join(dirname(linkedObjects), 'external-git-objects')
  await rename(join(linkedObjects, '.git', 'objects'), linkedObjectsDirectory)
  await symlink(linkedObjectsDirectory, join(linkedObjects, '.git', 'objects'))
  await expect(verifyPublicTree(linkedObjects)).rejects.toThrow(
    /\.git\/objects.*real local directory/i,
  )
})

it('rejects multiply linked worktree and Git metadata files', async () => {
  const linkedWorktreeFile = await exportedRepository()
  await link(
    join(linkedWorktreeFile, 'packages', 'agent-cli', 'README.md'),
    join(dirname(linkedWorktreeFile), 'external-readme-link'),
  )
  await expect(
    verifyPublicTree(linkedWorktreeFile, { mode: 'snapshot-only' }),
  ).rejects.toThrow(/worktree.*multiply linked|multiply linked.*worktree/i)

  const linkedMetadataFile = await exportedRepository()
  await link(
    join(linkedMetadataFile, '.git', 'config'),
    join(dirname(linkedMetadataFile), 'external-config-link'),
  )
  await expect(
    verifyPublicTree(linkedMetadataFile, { mode: 'snapshot-only' }),
  ).rejects.toThrow(/Git metadata.*multiply linked|multiply linked.*Git metadata/i)
})

it('rejects nested symlinks throughout Git object and ref storage in snapshot mode', async () => {
  const linkedObjectFanout = await exportedRepository()
  const objectsDirectory = join(linkedObjectFanout, '.git', 'objects')
  const fanouts = (await readdir(objectsDirectory, { withFileTypes: true }))
    .filter((entry) => entry.isDirectory() && /^[0-9a-f]{2}$/.test(entry.name))
  expect(fanouts.length).toBeGreaterThan(0)
  const objectFanout = join(objectsDirectory, fanouts[0].name)
  const externalFanout = join(dirname(linkedObjectFanout), 'external-object-fanout')
  await rename(objectFanout, externalFanout)
  await symlink(externalFanout, objectFanout)
  await expect(
    verifyPublicTree(linkedObjectFanout, { mode: 'snapshot-only' }),
  ).rejects.toThrow(/Git metadata.*symlink|symlink.*Git metadata/i)

  const linkedRefs = await exportedRepository()
  const headsDirectory = join(linkedRefs, '.git', 'refs', 'heads')
  const externalHeads = join(dirname(linkedRefs), 'external-heads')
  await rename(headsDirectory, externalHeads)
  await symlink(externalHeads, headsDirectory)
  await expect(
    verifyPublicTree(linkedRefs, { mode: 'snapshot-only' }),
  ).rejects.toThrow(/Git metadata.*symlink|symlink.*Git metadata/i)
})

it('rejects symlinked Git control files including packed refs', async () => {
  for (const relative of ['index', 'HEAD', 'config']) {
    const destination = await exportedRepository()
    const metadataPath = join(destination, '.git', relative)
    const externalPath = join(dirname(destination), `external-${relative.toLowerCase()}`)
    await rename(metadataPath, externalPath)
    await symlink(externalPath, metadataPath)
    await expect(
      verifyPublicTree(destination, { mode: 'snapshot-only' }),
    ).rejects.toThrow(/Git metadata.*symlink|symlink.*Git metadata/i)
  }

  const packedRefs = await exportedRepository()
  await execFileAsync('git', ['pack-refs', '--all'], { cwd: packedRefs })
  const packedRefsPath = join(packedRefs, '.git', 'packed-refs')
  const externalPackedRefs = join(dirname(packedRefs), 'external-packed-refs')
  await rename(packedRefsPath, externalPackedRefs)
  await symlink(externalPackedRefs, packedRefsPath)
  await expect(
    verifyPublicTree(packedRefs, { mode: 'snapshot-only' }),
  ).rejects.toThrow(/Git metadata.*symlink|symlink.*Git metadata/i)
})

it('rejects special files anywhere in dedicated Git metadata', async () => {
  const destination = await exportedRepository()
  await execFileAsync('mkfifo', [join(destination, '.git', 'untrusted-metadata-pipe')])
  await expect(
    verifyPublicTree(destination, { mode: 'snapshot-only' }),
  ).rejects.toThrow(/Git metadata.*special|special.*Git metadata/i)
})

it('rejects common-directory redirection before external configuration can block', async () => {
  const destination = await exportedRepository()
  const externalCommon = join(dirname(destination), 'external-common-directory')
  const externalConfigPipe = join(dirname(destination), 'external-config-pipe')
  await mkdir(externalCommon)
  await execFileAsync('mkfifo', [externalConfigPipe])
  await writeFile(
    join(externalCommon, 'config'),
    `[include]\n\tpath = ${externalConfigPipe}\n`,
  )
  await writeFile(join(destination, '.git', 'CommonDir'), '../../external-common-directory\n')

  let timeout: ReturnType<typeof setTimeout> | undefined
  const result = await Promise.race([
    verifyPublicTree(destination, { mode: 'snapshot-only' }).then(
      () => null,
      (reason: unknown) => reason,
    ),
    new Promise<'timed out'>((resolve) => {
      timeout = setTimeout(() => resolve('timed out'), 2_000)
    }),
  ])
  if (timeout !== undefined) clearTimeout(timeout)
  expect(result).toBeInstanceOf(Error)
  expect((result as Error).message).toMatch(/linked-worktree Git metadata/i)
  expect((result as Error).message).not.toContain(externalConfigPipe)
}, 5_000)

it('rejects linked-worktree control files and registered worktrees', async () => {
  const gitdirRepository = await exportedRepository()
  await writeFile(join(gitdirRepository, '.git', 'GitDir'), '/not-followed\n')
  await expect(
    verifyPublicTree(gitdirRepository, { mode: 'snapshot-only' }),
  ).rejects.toThrow(/linked-worktree Git metadata/i)

  const worktreeRepository = await exportedRepository()
  const linkedWorktree = join(dirname(worktreeRepository), 'external-linked-worktree')
  await execFileAsync('git', ['worktree', 'add', '--detach', linkedWorktree, 'HEAD'], {
    cwd: worktreeRepository,
  })
  const worktrees = join(worktreeRepository, '.git', 'worktrees')
  const temporaryWorktrees = join(worktreeRepository, '.git', 'worktrees-case-change')
  await rename(worktrees, temporaryWorktrees)
  await rename(temporaryWorktrees, join(worktreeRepository, '.git', 'WorkTrees'))
  await expect(
    verifyPublicTree(worktreeRepository, { mode: 'snapshot-only' }),
  ).rejects.toThrow(/linked-worktree Git metadata/i)
})

it('case-folds every security-sensitive Git metadata spelling', async () => {
  const attributesRepository = await exportedRepository()
  const info = join(attributesRepository, '.git', 'info')
  const temporaryInfo = join(attributesRepository, '.git', 'info-case-change')
  await rename(info, temporaryInfo)
  await rename(temporaryInfo, join(attributesRepository, '.git', 'Info'))
  await writeFile(join(attributesRepository, '.git', 'Info', 'Attributes'), '* filter=evil\n')
  await expect(
    verifyPublicTree(attributesRepository, { mode: 'snapshot-only' }),
  ).rejects.toThrow(/repository attributes/i)

  const worktreeConfigRepository = await exportedRepository()
  await writeFile(join(worktreeConfigRepository, '.git', 'Config.WorkTree'), '[core]\n')
  await expect(
    verifyPublicTree(worktreeConfigRepository, { mode: 'snapshot-only' }),
  ).rejects.toThrow(/unsafe local Git configuration/i)

  const promisorRepository = await exportedRepository()
  const pack = join(promisorRepository, '.git', 'objects', 'pack')
  const temporaryPack = join(promisorRepository, '.git', 'objects', 'pack-case-change')
  await rename(pack, temporaryPack)
  await rename(temporaryPack, join(promisorRepository, '.git', 'objects', 'Pack'))
  await writeFile(
    join(promisorRepository, '.git', 'objects', 'Pack', 'untrusted.PROMISOR'),
    '',
  )
  await expect(
    verifyPublicTree(promisorRepository, { mode: 'snapshot-only' }),
  ).rejects.toThrow(/partial clone|promisor storage/i)
}, 20_000)

it('rejects repository-configured filesystem monitor commands without executing them', async () => {
  const destination = await exportedRepository()
  const marker = join(dirname(destination), 'fsmonitor-ran')
  const monitor = join(dirname(destination), 'fsmonitor-hook.sh')
  await writeFile(monitor, `#!/bin/sh\n: > ${JSON.stringify(marker)}\nprintf '1\\0'\n`)
  await chmod(monitor, 0o755)
  await execFileAsync('git', ['config', 'core.fsmonitor', monitor], { cwd: destination })
  await execFileAsync('git', ['config', 'core.fsmonitorHookVersion', '2'], { cwd: destination })
  const error = await verifyPublicTree(destination, { mode: 'snapshot-only' }).then(
    () => null,
    (reason: unknown) => reason,
  )
  expect(error).toBeInstanceOf(Error)
  expect((error as Error).message).toMatch(/unsafe local Git configuration/i)
  expect((error as Error).message).not.toContain(monitor)
  expect((error as Error).message).not.toContain(marker)
  await expect(stat(marker)).rejects.toMatchObject({ code: 'ENOENT' })
})

it('rejects repository attributes before a clean filter can execute or leak stderr', async () => {
  const destination = await exportedRepository()
  const marker = join(dirname(destination), 'clean-filter-ran')
  const driver = join(dirname(destination), 'clean-filter.sh')
  const injectedStderr = 'INJECTED_FILTER_STDERR'
  await writeFile(
    driver,
    `#!/bin/sh\n: > ${JSON.stringify(marker)}\nprintf '${injectedStderr}\\n' >&2\ncat\n`,
  )
  await chmod(driver, 0o755)
  await writeFile(
    join(destination, '.git', 'info', 'attributes'),
    'packages/agent-cli/README.md filter=evil\n',
  )
  await execFileAsync('git', ['config', 'filter.evil.clean', driver], { cwd: destination })
  const error = await verifyPublicTree(destination, { mode: 'snapshot-only' }).then(
    () => null,
    (reason: unknown) => reason,
  )
  expect(error).toBeInstanceOf(Error)
  expect((error as Error).message).toMatch(/repository attributes/i)
  expect((error as Error).message).not.toContain(injectedStderr)
  expect((error as Error).message).not.toContain(driver)
  expect((error as Error).message).not.toContain(marker)
  await expect(stat(marker)).rejects.toMatchObject({ code: 'ENOENT' })
})

it('rejects executable and external local Git configuration before normal Git commands', async () => {
  const cases = [
    ['include.path', 'external-config'],
    ['filter.unused.clean', 'external-helper'],
    ['diff.unused.textconv', 'external-helper'],
    ['diff.orderFile', 'external-helper'],
    ['core.hooksPath', 'external-hooks'],
    ['log.showSignature', 'false'],
    ['log.mailmap', 'false'],
    ['mailmap.file', 'external-helper'],
    ['mailmap.blob', 'external-helper'],
    ['gpg.program', 'external-helper'],
    ['fsck.skipList', 'external-skip-list'],
  ]
  for (const [key, valueName] of cases) {
    const destination = await exportedRepository()
    const value = valueName === 'false' ? valueName : join(dirname(destination), valueName)
    if (valueName !== 'false') await writeFile(value, '')
    await execFileAsync('git', ['config', key, value], { cwd: destination })
    await expect(
      verifyPublicTree(destination, { mode: 'snapshot-only' }),
    ).rejects.toThrow(/unsafe local Git configuration/i)
  }
}, 20_000)

it('rejects worktree-specific Git configuration before it can affect commands', async () => {
  const destination = await exportedRepository()
  await execFileAsync('git', ['config', 'core.repositoryformatversion', '1'], {
    cwd: destination,
  })
  await execFileAsync('git', ['config', 'extensions.worktreeConfig', 'true'], {
    cwd: destination,
  })
  await execFileAsync('git', ['config', '--worktree', 'core.fsmonitor', '/not-executed'], {
    cwd: destination,
  })
  await expect(
    verifyPublicTree(destination, { mode: 'snapshot-only' }),
  ).rejects.toThrow(/unsafe local Git configuration/i)
})

it('rejects an external object alternate before snapshot object reads', async () => {
  const destination = await exportedRepository()
  const { stdout: blobOutput } = await execFileAsync(
    'git', ['rev-parse', 'HEAD:packages/agent-cli/README.md'],
    { cwd: destination, encoding: 'utf8' },
  )
  const blob = blobOutput.trim()
  const externalObjects = join(dirname(destination), 'external-alternate-objects')
  const externalFanout = join(externalObjects, blob.slice(0, 2))
  await mkdir(externalFanout, { recursive: true })
  await rename(
    join(destination, '.git', 'objects', blob.slice(0, 2), blob.slice(2)),
    join(externalFanout, blob.slice(2)),
  )
  await writeFile(
    join(destination, '.git', 'objects', 'info', 'alternates'),
    `${externalObjects}\n`,
  )
  await expect(
    verifyPublicTree(destination, { mode: 'snapshot-only' }),
  ).rejects.toThrow(/alternate Git object stores/i)
})

it('rejects grafts and HTTP alternates in snapshot mode', async () => {
  const grafted = await exportedRepository()
  const { stdout: head } = await execFileAsync('git', ['rev-parse', 'HEAD'], {
    cwd: grafted,
    encoding: 'utf8',
  })
  await writeFile(join(grafted, '.git', 'info', 'grafts'), `${head.trim()}\n`)
  await expect(
    verifyPublicTree(grafted, { mode: 'snapshot-only' }),
  ).rejects.toThrow(/legacy Git grafts/i)

  const httpAlternate = await exportedRepository()
  await writeFile(
    join(httpAlternate, '.git', 'objects', 'info', 'http-alternates'),
    'https://invalid.example/objects\n',
  )
  await expect(
    verifyPublicTree(httpAlternate, { mode: 'snapshot-only' }),
  ).rejects.toThrow(/alternate Git object stores/i)
})

it('recomputes each snapshot blob ID instead of trusting a loose-object filename', async () => {
  const destination = await exportedRepository()
  const relative = 'packages/agent-cli/README.md'
  const { stdout: blobOutput } = await execFileAsync(
    'git', ['rev-parse', `HEAD:${relative}`],
    { cwd: destination, encoding: 'utf8' },
  )
  const blob = blobOutput.trim()
  const tampered = Buffer.from('scanner-safe tampered worktree bytes\n')
  const rawObject = Buffer.concat([
    Buffer.from(`blob ${tampered.byteLength}\0`),
    tampered,
  ])
  const objectPath = join(destination, '.git', 'objects', blob.slice(0, 2), blob.slice(2))
  await chmod(objectPath, 0o644)
  await writeFile(
    objectPath,
    deflateSync(rawObject),
  )
  await writeFile(join(destination, relative), tampered)
  await expect(
    verifyPublicTree(destination, { mode: 'snapshot-only' }),
  ).rejects.toThrow(/blob object ID.*index/i)
})

it('rejects an oversized current file from metadata before reading its contents', async () => {
  const destination = await exportedRepository()
  await truncate(join(destination, 'packages/agent-cli/README.md'), 8 * 1024 * 1024 + 1)
  await expect(
    verifyPublicTree(destination, { mode: 'snapshot-only' }),
  ).rejects.toThrow(/size limit/i)
})

it('rejects unreachable imported Git objects during full verification', async () => {
  const destination = await exportedRepository()
  const unreachableSource = join(dirname(destination), 'unreachable-source.txt')
  await writeFile(unreachableSource, 'unreachable imported object\n')
  await execFileAsync('git', ['hash-object', '-w', unreachableSource], { cwd: destination })
  await expect(verifyPublicTree(destination)).rejects.toThrow(/unreachable Git object/i)
})

it('rejects partial-clone configuration and promisor pack markers in every mode', async () => {
  const configured = await exportedRepository()
  await execFileAsync('git', ['config', 'remote.origin.promisor', 'true'], { cwd: configured })
  await expect(
    verifyPublicTree(configured, { mode: 'snapshot-only' }),
  ).rejects.toThrow(/partial clone|promisor/i)

  const marked = await exportedRepository()
  await writeFile(join(marked, '.git', 'objects', 'pack', 'untrusted.promisor'), '')
  await expect(
    verifyPublicTree(marked, { mode: 'snapshot-only' }),
  ).rejects.toThrow(/partial clone|promisor/i)
})

for (const indexFlag of ['--skip-worktree', '--assume-unchanged']) {
  it(`rejects ${indexFlag} even when it hides changed worktree bytes`, async () => {
    const destination = await exportedRepository()
    const relative = 'packages/agent-cli/README.md'
    await execFileAsync('git', ['update-index', indexFlag, relative], { cwd: destination })
    await writeFile(join(destination, relative), 'scanner-safe but uncommitted replacement\n')
    const { stdout: hiddenStatus } = await execFileAsync(
      'git', ['status', '--porcelain=v1', '-z', '--untracked-files=all'],
      { cwd: destination, encoding: 'utf8' },
    )
    expect(hiddenStatus).toBe('')
    await expect(
      verifyPublicTree(destination, { mode: 'snapshot-only' }),
    ).rejects.toThrow(/non-normal index flag/i)
  })
}

it('rejects executable-mode drift even when local Git configuration hides it', async () => {
  const destination = await exportedRepository()
  const relative = 'packages/agent-cli/README.md'
  await execFileAsync('git', ['config', 'core.fileMode', 'false'], { cwd: destination })
  await chmod(join(destination, relative), 0o755)
  const { stdout: hiddenStatus } = await execFileAsync(
    'git', ['status', '--porcelain=v1', '-z', '--untracked-files=all'],
    { cwd: destination, encoding: 'utf8' },
  )
  expect(hiddenStatus).toBe('')
  await expect(
    verifyPublicTree(destination, { mode: 'snapshot-only' }),
  ).rejects.toThrow(/executable state.*index/i)
})

it('rejects ignored credential files and other ignored worktree extras', async () => {
  for (const relative of ['.npmrc', 'ignored-extra.txt']) {
    const destination = await exportedRepository()
    await writeFile(join(destination, '.git', 'info', 'exclude'), `${relative}\n`)
    await writeFile(join(destination, relative), 'ignored but present\n')
    const { stdout: hiddenStatus } = await execFileAsync(
      'git', ['status', '--porcelain=v1', '-z', '--untracked-files=all'],
      { cwd: destination, encoding: 'utf8' },
    )
    expect(hiddenStatus).toBe('')
    const error = await verifyPublicTree(destination, { mode: 'snapshot-only' }).then(
      () => null,
      (reason: unknown) => reason,
    )
    expect(error).toBeInstanceOf(Error)
    expect((error as Error).message).toMatch(/unallowlisted worktree path/i)
    expect((error as Error).message).not.toContain(relative)
    expect((error as Error).message).not.toContain(destination)
  }
})

it('ignores inherited Git metadata overrides and still finds unsafe target history', async () => {
  const destination = await exportedRepository()
  const safeRepository = await exportedRepository()
  const relative = 'packages/agent-cli/README.md'
  const path = join(destination, relative)
  const original = await readFile(path, 'utf8')
  const credential = ['npm', 'm'.repeat(36)].join('_')
  await writeFile(path, `unsafe history ${credential}\n`)
  await execFileAsync('git', ['add', relative], { cwd: destination })
  await commitRelease(destination)
  await writeFile(path, original)
  await execFileAsync('git', ['add', relative], { cwd: destination })
  await commitRelease(destination)
  const previousDirectory = process.env.GIT_DIR
  const previousWorkTree = process.env.GIT_WORK_TREE
  process.env.GIT_DIR = join(safeRepository, '.git')
  process.env.GIT_WORK_TREE = destination
  try {
    await expect(verifyPublicTree(destination)).rejects.toThrow(/credential pattern/i)
  } finally {
    if (previousDirectory === undefined) delete process.env.GIT_DIR
    else process.env.GIT_DIR = previousDirectory
    if (previousWorkTree === undefined) delete process.env.GIT_WORK_TREE
    else process.env.GIT_WORK_TREE = previousWorkTree
  }
})

it('rejects shallow and legacy-grafted repository history', async () => {
  const shallow = await exportedRepository()
  const { stdout: shallowHead } = await execFileAsync('git', ['rev-parse', 'HEAD'], {
    cwd: shallow,
    encoding: 'utf8',
  })
  await writeFile(join(shallow, '.git', 'shallow'), shallowHead)
  await expect(
    verifyPublicTree(shallow, { mode: 'snapshot-only' }),
  ).resolves.toMatchObject({ trackedFiles: expect.any(Number) })
  await expect(verifyPublicTree(shallow)).rejects.toThrow(/complete, not shallow/i)

  const grafted = await exportedRepository()
  const { stdout: graftedHead } = await execFileAsync('git', ['rev-parse', 'HEAD'], {
    cwd: grafted,
    encoding: 'utf8',
  })
  await writeFile(join(grafted, '.git', 'info', 'grafts'), graftedHead)
  await expect(verifyPublicTree(grafted)).rejects.toThrow(/legacy Git grafts/i)
})

it('rejects an oversized blob hidden in an allowed historical path', async () => {
  const destination = await exportedRepository()
  const relative = 'packages/agent-cli/README.md'
  const path = join(destination, relative)
  const original = await readFile(path)
  await writeFile(path, Buffer.alloc(8 * 1024 * 1024 + 1, 0x61))
  await execFileAsync('git', ['add', relative], { cwd: destination })
  await commitRelease(destination)
  await writeFile(path, original)
  await execFileAsync('git', ['add', relative], { cwd: destination })
  await commitRelease(destination)
  await expect(verifyPublicTree(destination)).rejects.toThrow(/size limit/i)
})

it('rejects an unexpected file even under the agent package prefix', async () => {
  const destination = await exportedRepository()
  const unexpected = join(destination, 'packages/agent-cli/coinbase-notes.txt')
  await writeFile(unexpected, 'not part of the reviewed source manifest\n')
  await execFileAsync('git', ['add', 'packages/agent-cli/coinbase-notes.txt'], {
    cwd: destination,
  })
  await commitRelease(destination)
  await expect(verifyPublicTree(destination, { mode: 'snapshot-only' })).rejects.toThrow(
    /disallowed path/i,
  )
  await expect(verifyPublicTree(destination)).rejects.toThrow(/disallowed path/i)

  const secondDestination = join(dirname(destination), 'second-export')
  await expect(exportPublicSource(secondDestination, destination)).rejects.toThrow(
    /allowlist mismatch.*coinbase-notes/i,
  )
})

it('rejects a public tree that silently removes a required security test', async () => {
  const destination = await exportedRepository()
  await execFileAsync('git', ['rm', 'packages/agent-cli/test/api-security.test.ts'], {
    cwd: destination,
  })
  await commitRelease(destination)
  await expect(verifyPublicTree(destination, { mode: 'snapshot-only' })).rejects.toThrow(
    /missing packages\/agent-cli\/test\/api-security\.test\.ts/i,
  )
  await expect(verifyPublicTree(destination)).rejects.toThrow(
    /missing packages\/agent-cli\/test\/api-security\.test\.ts/i,
  )
})

it('snapshot-only mode still rejects changed root and package manifests', async () => {
  const rootChanged = await exportedRepository()
  const rootManifestPath = join(rootChanged, 'package.json')
  const rootManifest = JSON.parse(await readFile(rootManifestPath, 'utf8'))
  await writeFile(rootManifestPath, `${JSON.stringify({ ...rootManifest, unexpected: true }, null, 2)}\n`)
  await execFileAsync('git', ['add', 'package.json'], { cwd: rootChanged })
  await commitRelease(rootChanged)
  await expect(verifyPublicTree(rootChanged, { mode: 'snapshot-only' })).rejects.toThrow(
    /root manifest differs/i,
  )

  const packageChanged = await exportedRepository()
  const packageManifestPath = join(packageChanged, 'packages/agent-cli/package.json')
  const packageManifest = JSON.parse(await readFile(packageManifestPath, 'utf8'))
  await writeFile(
    packageManifestPath,
    `${JSON.stringify({ ...packageManifest, name: '@invalid/agent' }, null, 2)}\n`,
  )
  await execFileAsync('git', ['add', 'packages/agent-cli/package.json'], {
    cwd: packageChanged,
  })
  await commitRelease(packageChanged)
  await expect(verifyPublicTree(packageChanged, { mode: 'snapshot-only' })).rejects.toThrow(
    /invalid package identity or version/i,
  )
})

for (const version of ['0.1.0', '0.1.1', '0.1.2']) {
  it(`rejects retired package version ${version} without relying on a tag`, async () => {
    const destination = await exportedRepository()
    const packageManifestPath = join(destination, 'packages/agent-cli/package.json')
    const packageManifest = JSON.parse(await readFile(packageManifestPath, 'utf8'))
    await writeFile(
      packageManifestPath,
      `${JSON.stringify({ ...packageManifest, version }, null, 2)}\n`,
    )
    await execFileAsync('git', ['add', 'packages/agent-cli/package.json'], {
      cwd: destination,
    })
    await execFileAsync(
      'git', ['commit', '-m', `release: publish @1f4bcai/agent@${version}`],
      {
        cwd: destination,
        env: {
          ...process.env,
          GIT_AUTHOR_DATE: PUBLIC_GIT_DATE,
          GIT_COMMITTER_DATE: PUBLIC_GIT_DATE,
        },
      },
    )

    await expect(
      verifyPublicTree(destination, { mode: 'snapshot-only' }),
    ).rejects.toThrow(/retired package version/i)
    await expect(verifyPublicTree(destination)).rejects.toThrow(/retired package version/i)
  })
}

it('snapshot-only mode still rejects unrelated lock records', async () => {
  const destination = await exportedRepository()
  const lockPath = join(destination, 'package-lock.json')
  const lock = JSON.parse(await readFile(lockPath, 'utf8'))
  lock.packages['node_modules/unrelated-package'] = { version: '1.0.0' }
  await writeFile(lockPath, `${JSON.stringify(lock, null, 2)}\n`)
  await execFileAsync('git', ['add', 'package-lock.json'], { cwd: destination })
  await commitRelease(destination)
  await expect(verifyPublicTree(destination, { mode: 'snapshot-only' })).rejects.toThrow(
    /public lock contains unrelated/i,
  )
})

it('rejects a historical symlink even after the current file is restored', async () => {
  const destination = await exportedRepository()
  const relative = 'packages/agent-cli/src/api.ts'
  const path = join(destination, relative)
  const original = await readFile(path, 'utf8')
  await rm(path)
  await symlink('mcp.ts', path)
  await execFileAsync('git', ['add', relative], { cwd: destination })
  await commitRelease(destination)
  await rm(path)
  await writeFile(path, original)
  await execFileAsync('git', ['add', relative], { cwd: destination })
  await commitRelease(destination)
  await expect(verifyPublicTree(destination)).rejects.toThrow(/special file mode/i)
})

it('rejects a historical gitlink even after the current file is restored', async () => {
  const destination = await exportedRepository()
  const relative = 'packages/agent-cli/src/api.ts'
  const { stdout: head } = await execFileAsync('git', ['rev-parse', 'HEAD'], {
    cwd: destination,
    encoding: 'utf8',
  })
  await execFileAsync(
    'git', ['update-index', '--add', '--cacheinfo', `160000,${head.trim()},${relative}`],
    { cwd: destination },
  )
  await commitRelease(destination)
  await execFileAsync('git', ['add', relative], { cwd: destination })
  await commitRelease(destination)
  await expect(verifyPublicTree(destination)).rejects.toThrow(/special file mode/i)
})

it('refuses credential-bearing source before writing an export', async () => {
  const source = await exportedRepository()
  const credential = ['npm', 'c'.repeat(36)].join('_')
  await writeFile(
    join(source, 'packages/agent-cli/README.md'),
    `accidental credential ${credential}\n`,
  )
  const target = join(dirname(source), 'credential-export')
  await expect(exportPublicSource(target, source)).rejects.toThrow(/credential|access token/i)
  await expect(readFile(join(target, 'package.json'), 'utf8')).rejects.toMatchObject({
    code: 'ENOENT',
  })
})

it('canonicalizes an intermediate symlink before destination containment checks', async () => {
  const source = await exportedRepository()
  const inside = join(source, 'empty-export-target')
  await mkdir(inside, { mode: 0o700 })
  const outside = await mkdtemp(join(tmpdir(), '1f4bc-export-link-'))
  cleanup.push(outside)
  const link = join(outside, 'source-link')
  await symlink(source, link)

  await expect(exportPublicSource(join(link, 'empty-export-target'), source))
    .rejects.toThrow(/outside the private repository/i)
  expect((await stat(inside)).isDirectory()).toBe(true)
})

it('rejects a pre-existing export target with non-private permissions', async () => {
  const source = await exportedRepository()
  const target = join(dirname(source), 'unsafe-existing-export')
  await mkdir(target, { mode: 0o700 })
  await chmod(target, 0o777)
  await expect(exportPublicSource(target, source)).rejects.toThrow(/private 0700 permissions/i)
})

it('accepts an empty current-user export target with private permissions', async () => {
  const source = await exportedRepository()
  const target = join(dirname(source), 'safe-existing-export')
  await mkdir(target, { mode: 0o700 })
  await chmod(target, 0o700)
  await expect(exportPublicSource(target, source)).resolves.toBe(await realpath(target))
  expect(JSON.parse(await readFile(join(target, 'package.json'), 'utf8'))).toMatchObject({
    name: '1f4bc-agent-release-source',
    private: true,
  })
})

it('exports only bytes that were already scanned even if source changes afterward', async () => {
  const source = await exportedRepository()
  const destination = join(dirname(source), 'snapshot-export')
  const sourceReadme = join(source, 'packages/agent-cli/README.md')
  const credential = ['npm', 'g'.repeat(36)].join('_')
  await exportPublicSource(destination, source, {
    afterSourceSnapshot: async () => {
      await writeFile(sourceReadme, `late replacement ${credential}\n`)
    },
  })
  expect(await readFile(join(destination, 'packages/agent-cli/README.md'), 'utf8'))
    .not.toContain(credential)
  expect(await readFile(sourceReadme, 'utf8')).toContain(credential)
})

it('rejects credential material hidden in commit metadata', async () => {
  const destination = await exportedRepository()
  const credential = ['npm', 'b'.repeat(36)].join('_')
  await execFileAsync('git', ['commit', '--allow-empty', '-m', `release note ${credential}`], {
    cwd: destination,
    env: {
      ...process.env,
      GIT_AUTHOR_DATE: PUBLIC_GIT_DATE,
      GIT_COMMITTER_DATE: PUBLIC_GIT_DATE,
    },
  })
  await expect(verifyPublicTree(destination)).rejects.toThrow(/commit object/i)
})

it('rejects credential material hidden in author or committer identity', async () => {
  const destination = await exportedRepository()
  const credential = ['npm', 'd'.repeat(36)].join('_')
  await execFileAsync('git', ['commit', '--allow-empty', '-m', 'safe subject'], {
    cwd: destination,
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: credential,
      GIT_AUTHOR_EMAIL: 'author@invalid.example',
      GIT_COMMITTER_NAME: 'release test',
      GIT_COMMITTER_EMAIL: 'release-test@invalid.example',
      GIT_AUTHOR_DATE: PUBLIC_GIT_DATE,
      GIT_COMMITTER_DATE: PUBLIC_GIT_DATE,
    },
  })
  await expect(verifyPublicTree(destination)).rejects.toThrow(/commit object/i)
})

it('rejects non-service author metadata without echoing it', async () => {
  const destination = await exportedRepository()
  await execFileAsync('git', ['commit', '--allow-empty', '-m', PUBLIC_GIT_MESSAGE], {
    cwd: destination,
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: 'Unapproved Contributor',
      GIT_AUTHOR_EMAIL: 'contributor@example.test',
      GIT_COMMITTER_NAME: PUBLIC_GIT_NAME,
      GIT_COMMITTER_EMAIL: PUBLIC_GIT_EMAIL,
      GIT_AUTHOR_DATE: '2026-08-25T00:01:00Z',
      GIT_COMMITTER_DATE: '2026-08-25T00:01:00Z',
    },
  })
  const error = await verifyPublicTree(destination).then(
    () => null,
    (reason: unknown) => reason,
  )
  expect(error).toBeInstanceOf(Error)
  expect((error as Error).message).toMatch(/organization-controlled Git identity/i)
  expect((error as Error).message).not.toContain('Unapproved Contributor')
  expect((error as Error).message).not.toContain('contributor@example.test')
})

it('rejects non-service committer metadata separately', async () => {
  const destination = await exportedRepository()
  await execFileAsync('git', ['commit', '--allow-empty', '-m', PUBLIC_GIT_MESSAGE], {
    cwd: destination,
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: PUBLIC_GIT_NAME,
      GIT_AUTHOR_EMAIL: PUBLIC_GIT_EMAIL,
      GIT_COMMITTER_NAME: 'Unapproved Committer',
      GIT_COMMITTER_EMAIL: 'committer@example.test',
      GIT_AUTHOR_DATE: '2026-08-25T00:01:00Z',
      GIT_COMMITTER_DATE: '2026-08-25T00:01:00Z',
    },
  })
  const error = await verifyPublicTree(destination).then(
    () => null,
    (reason: unknown) => reason,
  )
  expect(error).toBeInstanceOf(Error)
  expect((error as Error).message).toMatch(/organization-controlled Git identity/i)
  expect((error as Error).message).not.toContain('Unapproved Committer')
  expect((error as Error).message).not.toContain('committer@example.test')
})

it('rejects non-UTC service identity metadata', async () => {
  const destination = await exportedRepository()
  await execFileAsync('git', ['commit', '--allow-empty', '-m', PUBLIC_GIT_MESSAGE], {
    cwd: destination,
    env: {
      ...process.env,
      GIT_AUTHOR_DATE: '2026-08-25T00:01:00-07:00',
      GIT_COMMITTER_DATE: '2026-08-25T00:01:00-07:00',
    },
  })
  await expect(verifyPublicTree(destination)).rejects.toThrow(
    /organization-controlled Git identity/i,
  )
})

it('rejects arbitrary public commit messages', async () => {
  const destination = await exportedRepository()
  const injectedMessage = 'miscellaneous cleanup'
  await execFileAsync('git', ['commit', '--allow-empty', '-m', injectedMessage], {
    cwd: destination,
    env: {
      ...process.env,
      GIT_AUTHOR_DATE: PUBLIC_GIT_DATE,
      GIT_COMMITTER_DATE: PUBLIC_GIT_DATE,
    },
  })
  const error = await verifyPublicTree(destination).then(
    () => null,
    (reason: unknown) => reason,
  )
  expect(error).toBeInstanceOf(Error)
  expect((error as Error).message).toMatch(/release commit message/i)
  expect((error as Error).message).not.toContain(injectedMessage)
})

it('rejects a release message whose version differs from its tree', async () => {
  const destination = await exportedRepository()
  await execFileAsync(
    'git',
    ['commit', '--allow-empty', '-m', 'release: publish @1f4bcai/agent@9.9.9'],
    {
      cwd: destination,
      env: {
        ...process.env,
        GIT_AUTHOR_DATE: PUBLIC_GIT_DATE,
        GIT_COMMITTER_DATE: PUBLIC_GIT_DATE,
      },
    },
  )
  await expect(verifyPublicTree(destination)).rejects.toThrow(/release commit message/i)
})

it('rejects a duplicate raw author even when Git renders the allowed author', async () => {
  const destination = await exportedRepository()
  const commit = await installRawCommit(destination, 'duplicate-author-commit', [
    'author Unapproved Contributor <contributor@example.test> 1787616000 +0000',
    'author 1F4BC Release <support@1f4bc.com> 1787616000 +0000',
    'committer 1F4BC Release <support@1f4bc.com> 1787616000 +0000',
  ])
  const { stdout: renderedAuthor } = await execFileAsync(
    'git', ['show', '-s', '--format=%an <%ae>', commit],
    { cwd: destination, encoding: 'utf8' },
  )
  expect(renderedAuthor.trim()).toBe(`${PUBLIC_GIT_NAME} <${PUBLIC_GIT_EMAIL}>`)
  await expect(verifyPublicTree(destination)).rejects.toThrow(
    /unsupported metadata headers|strict Git object verification/i,
  )
})

it('rejects reordered raw author and committer headers', async () => {
  const destination = await exportedRepository()
  await installRawCommit(destination, 'reordered-identity-headers', [
    'committer 1F4BC Release <support@1f4bc.com> 1787616000 +0000',
    'author 1F4BC Release <support@1f4bc.com> 1787616000 +0000',
  ])
  await expect(verifyPublicTree(destination)).rejects.toThrow(
    /unsupported metadata headers|strict Git object verification/i,
  )
})

it('rejects a credential-free optional raw commit header', async () => {
  const destination = await exportedRepository()
  await installRawCommit(destination, 'optional-header-commit', [
    'author 1F4BC Release <support@1f4bc.com> 1787616000 +0000',
    'committer 1F4BC Release <support@1f4bc.com> 1787616000 +0000',
    'encoding UTF-8',
  ])
  await expect(verifyPublicTree(destination)).rejects.toThrow(/unsupported metadata headers/i)
})

it('accepts only the current lightweight release tag', async () => {
  const destination = await exportedRepository()
  await execFileAsync('git', ['tag', 'agent-v0.1.3'], { cwd: destination })
  await expect(verifyPublicTree(destination)).resolves.toMatchObject({
    trackedFiles: expect.any(Number),
  })
})

it('rejects a lightweight release tag whose version differs from its tree', async () => {
  const destination = await exportedRepository()
  await execFileAsync('git', ['tag', 'agent-v9.9.9'], { cwd: destination })
  await expect(verifyPublicTree(destination)).rejects.toThrow(/tag does not match its package tree/i)
})

for (const version of ['0.1.0', '0.1.1', '0.1.2']) {
  it(`rejects retired release tag agent-v${version} independently`, async () => {
    const destination = await exportedRepository()
    await execFileAsync('git', ['tag', `agent-v${version}`], { cwd: destination })
    await expect(verifyPublicTree(destination)).rejects.toThrow(/retired release tag/i)
  })
}

it('rejects annotated release tags', async () => {
  const annotated = await exportedRepository()
  await execFileAsync(
    'git',
    ['tag', '-a', 'agent-v0.1.3', '-m', 'release: publish @1f4bcai/agent@0.1.3'],
    { cwd: annotated },
  )
  await expect(verifyPublicTree(annotated)).rejects.toThrow(/lightweight release tags/i)
})

it('accepts the canonical optional origin refs', async () => {
  const destination = await exportedRepository()
  await execFileAsync('git', ['update-ref', 'refs/remotes/origin/main', 'HEAD'], {
    cwd: destination,
  })
  await execFileAsync(
    'git', ['symbolic-ref', 'refs/remotes/origin/HEAD', 'refs/remotes/origin/main'],
    { cwd: destination },
  )
  await expect(verifyPublicTree(destination)).resolves.toMatchObject({
    trackedFiles: expect.any(Number),
  })
})

it('requires a canonical main ref even when a valid-looking release tag exists', async () => {
  const destination = await exportedRepository()
  await execFileAsync('git', ['tag', 'agent-v0.1.3'], { cwd: destination })
  await execFileAsync('git', ['switch', '--detach'], { cwd: destination })
  await execFileAsync('git', ['update-ref', '-d', 'refs/heads/main'], { cwd: destination })
  await expect(verifyPublicTree(destination)).rejects.toThrow(/canonical main ref/i)
})

it('requires local and remote canonical main refs to resolve identically', async () => {
  const destination = await exportedRepository()
  const { stdout: originalMain } = await execFileAsync('git', ['rev-parse', 'HEAD'], {
    cwd: destination,
    encoding: 'utf8',
  })
  await execFileAsync('git', ['commit', '--allow-empty', '-m', PUBLIC_GIT_MESSAGE], {
    cwd: destination,
    env: {
      ...process.env,
      GIT_AUTHOR_DATE: PUBLIC_GIT_DATE,
      GIT_COMMITTER_DATE: PUBLIC_GIT_DATE,
    },
  })
  await execFileAsync(
    'git', ['update-ref', 'refs/remotes/origin/main', originalMain.trim()],
    { cwd: destination },
  )
  await expect(verifyPublicTree(destination)).rejects.toThrow(/canonical main refs.*differ/i)
})

it('rejects a valid-looking release tag disconnected from canonical main', async () => {
  const destination = await exportedRepository()
  const { stdout: tree } = await execFileAsync('git', ['rev-parse', 'HEAD^{tree}'], {
    cwd: destination,
    encoding: 'utf8',
  })
  const { stdout: disconnectedCommit } = await execFileAsync(
    'git', ['commit-tree', tree.trim(), '-m', PUBLIC_GIT_MESSAGE],
    {
      cwd: destination,
      encoding: 'utf8',
      env: {
        ...process.env,
        GIT_AUTHOR_DATE: '2026-08-25T00:01:00Z',
        GIT_COMMITTER_DATE: '2026-08-25T00:01:00Z',
      },
    },
  )
  await execFileAsync(
    'git', ['update-ref', 'refs/tags/agent-v0.1.3', disconnectedCommit.trim()],
    { cwd: destination },
  )
  await expect(verifyPublicTree(destination)).rejects.toThrow(/release tag.*canonical main/i)
})

it('rejects a detached canonical-format orphan HEAD while main remains unchanged', async () => {
  const destination = await exportedRepository()
  const { stdout: tree } = await execFileAsync('git', ['rev-parse', 'HEAD^{tree}'], {
    cwd: destination,
    encoding: 'utf8',
  })
  const { stdout: orphanCommit } = await execFileAsync(
    'git', ['commit-tree', tree.trim(), '-m', PUBLIC_GIT_MESSAGE],
    {
      cwd: destination,
      encoding: 'utf8',
      env: {
        ...process.env,
        GIT_AUTHOR_DATE: '2026-08-25T00:01:00Z',
        GIT_COMMITTER_DATE: '2026-08-25T00:01:00Z',
      },
    },
  )
  await execFileAsync('git', ['switch', '--detach', orphanCommit.trim()], { cwd: destination })
  await expect(verifyPublicTree(destination)).rejects.toThrow(
    /HEAD.*canonical main.*release tag/i,
  )
})

it('rejects an extra local source branch', async () => {
  const destination = await exportedRepository()
  await execFileAsync('git', ['branch', 'source-copy'], { cwd: destination })
  await expect(verifyPublicTree(destination)).rejects.toThrow(/unexpected public Git ref/i)
})

it('snapshot-only mode accepts a synthetic pull-request merge while full mode rejects it', async () => {
  const destination = await exportedRepository()
  await execFileAsync('git', ['switch', '-c', 'pull-request-candidate'], { cwd: destination })
  await execFileAsync('git', ['commit', '--allow-empty', '-m', 'candidate snapshot'], {
    cwd: destination,
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: 'Pull Request Contributor',
      GIT_AUTHOR_EMAIL: 'contributor@example.test',
      GIT_COMMITTER_NAME: 'Pull Request Contributor',
      GIT_COMMITTER_EMAIL: 'contributor@example.test',
      GIT_AUTHOR_DATE: '2026-08-25T00:01:00Z',
      GIT_COMMITTER_DATE: '2026-08-25T00:01:00Z',
    },
  })
  await execFileAsync('git', ['switch', 'main'], { cwd: destination })
  await execFileAsync(
    'git',
    ['merge', '--no-ff', 'pull-request-candidate', '-m', 'Merge pull request candidate'],
    {
      cwd: destination,
      env: {
        ...process.env,
        GIT_AUTHOR_NAME: 'Pull Request Merge',
        GIT_AUTHOR_EMAIL: 'merge@example.test',
        GIT_COMMITTER_NAME: 'Pull Request Merge',
        GIT_COMMITTER_EMAIL: 'merge@example.test',
        GIT_AUTHOR_DATE: '2026-08-25T00:02:00Z',
        GIT_COMMITTER_DATE: '2026-08-25T00:02:00Z',
      },
    },
  )
  await execFileAsync('git', ['branch', '-D', 'pull-request-candidate'], { cwd: destination })

  await expect(verifyPublicTree(destination)).rejects.toThrow(/unsupported metadata headers/i)
  await expect(verifyPublicTree(destination, { mode: 'snapshot-only' })).resolves.toMatchObject({
    trackedFiles: expect.any(Number),
    lockedPackages: expect.any(Number),
  })
})

it('rejects credential material hidden in raw signed-commit headers', async () => {
  const destination = await exportedRepository()
  const credential = ['npm', 'e'.repeat(36)].join('_')
  await installRawCommit(destination, 'raw-signed-commit', [
    'author 1F4BC Release <support@1f4bc.com> 1787486400 +0000',
    'committer 1F4BC Release <support@1f4bc.com> 1787486400 +0000',
    'gpgsig -----BEGIN PGP SIGNATURE-----',
    ` ${credential}`,
    ' -----END PGP SIGNATURE-----',
  ], 'safe visible message')
  await expect(verifyPublicTree(destination)).rejects.toThrow(/commit object/i)
})

it('rejects credential material hidden in any Git ref name', async () => {
  const destination = await exportedRepository()
  const credential = ['npm', 'f'.repeat(36)].join('_')
  const { stdout: head } = await execFileAsync('git', ['rev-parse', 'HEAD'], {
    cwd: destination,
    encoding: 'utf8',
  })
  await execFileAsync(
    'git', ['update-ref', `refs/heads/${credential}`, head.trim()],
    { cwd: destination },
  )
  await expect(verifyPublicTree(destination)).rejects.toThrow(/ref name/i)
})
