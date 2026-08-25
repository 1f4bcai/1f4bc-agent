import { execFile } from 'node:child_process'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { afterEach, describe, expect, it } from 'vitest'
import { exportPublicSource } from '../scripts/export-public-source.mjs'
import {
  assertSuccessfulCandidateCi,
  assertReleaseAppContext,
  promoteReleaseCandidate,
} from '../scripts/promote-release-candidate.mjs'

const execFileAsync = promisify(execFile)
const cleanup: string[] = []
const APP_CONTEXT = Object.freeze({
  repository: '1f4bcai/1f4bc-agent',
  eventName: 'repository_dispatch',
  actor: '1f4bc-release-automation[bot]',
  actorId: '321246169',
  triggeringActor: '1f4bc-release-automation[bot]',
  expectedActor: '1f4bc-release-automation[bot]',
  expectedActorId: '321246169',
})

async function git(cwd: string, args: string[], env: NodeJS.ProcessEnv = {}) {
  return execFileAsync('git', args, {
    cwd,
    encoding: 'utf8',
    env: {
      ...process.env,
      GIT_CONFIG_NOSYSTEM: '1',
      GIT_CONFIG_GLOBAL: '/dev/null',
      ...env,
    },
  })
}

async function configurePublicGit(repository: string) {
  await git(repository, ['config', 'maintenance.auto', 'false'])
  await git(repository, ['config', 'gc.auto', '0'])
  await git(repository, ['config', 'user.name', '1F4BC Release'])
  await git(repository, ['config', 'user.email', 'support@1f4bc.com'])
}

async function commit(repository: string, message: string, date: string) {
  await git(repository, ['add', '--all'])
  await git(repository, ['commit', '-m', message], {
    GIT_AUTHOR_DATE: date,
    GIT_COMMITTER_DATE: date,
  })
  return (await git(repository, ['rev-parse', 'HEAD'])).stdout.trim()
}

async function setExportVersion(repository: string, version: string) {
  const rootPath = join(repository, 'package.json')
  const packagePath = join(repository, 'packages/agent-cli/package.json')
  const lockPath = join(repository, 'package-lock.json')
  const root = JSON.parse(await readFile(rootPath, 'utf8'))
  const manifest = JSON.parse(await readFile(packagePath, 'utf8'))
  const lock = JSON.parse(await readFile(lockPath, 'utf8'))
  root.version = version
  manifest.version = version
  lock.version = version
  lock.packages[''].version = version
  lock.packages['packages/agent-cli'].version = version
  await writeFile(rootPath, `${JSON.stringify(root, null, 2)}\n`)
  await writeFile(packagePath, `${JSON.stringify(manifest, null, 2)}\n`)
  await writeFile(lockPath, `${JSON.stringify(lock, null, 2)}\n`)
}

type PromotionFixture = {
  authority: string
  base: string
  candidate: string
  candidateRef: string
  remote: string
  source: string
}

async function promotionFixture(options: {
  alterAuthority?: boolean
  extraParent?: boolean
} = {}): Promise<PromotionFixture> {
  const parent = await mkdtemp(join(tmpdir(), '1f4bc-candidate-promotion-'))
  cleanup.push(parent)
  const source = join(parent, 'source')
  const remote = join(parent, 'remote.git')
  const authority = join(parent, 'authority')
  await exportPublicSource(source)
  await setExportVersion(source, '0.1.3')
  await git(source, ['init', '-b', 'main'])
  await configurePublicGit(source)
  const base = await commit(
    source,
    'release: publish @1f4bcai/agent@0.1.3',
    '2026-08-25T00:00:00Z',
  )
  await git(parent, ['init', '--bare', remote])
  await git(source, ['remote', 'add', 'origin', remote])
  await git(source, ['tag', 'agent-v0.1.3', base])
  await git(source, ['push', 'origin', 'main:main', 'agent-v0.1.3'])
  await git(parent, ['clone', '--branch', 'main', remote, authority])
  await configurePublicGit(authority)

  if (options.extraParent) {
    await git(source, ['commit', '--allow-empty', '-m', 'unapproved intermediate'], {
      GIT_AUTHOR_DATE: '2026-08-25T00:00:30Z',
      GIT_COMMITTER_DATE: '2026-08-25T00:00:30Z',
    })
  }
  await setExportVersion(source, '0.1.4')
  if (options.alterAuthority) {
    const workflow = join(source, '.github/workflows/release-agent-cli.yml')
    await writeFile(workflow, `${await readFile(workflow, 'utf8')}\n# candidate policy change\n`)
  }
  const candidate = await commit(
    source,
    'release: publish @1f4bcai/agent@0.1.4',
    '2026-08-25T00:01:00Z',
  )
  const candidateRef = `agent-candidate-0.1.4-${candidate.slice(0, 12)}`
  await git(source, ['push', 'origin', `HEAD:refs/heads/${candidateRef}`])
  return { authority, base, candidate, candidateRef, remote, source }
}

function options(fixture: PromotionFixture) {
  return {
    authorityRoot: fixture.authority,
    baseCommit: fixture.base,
    candidateCommit: fixture.candidate,
    candidateRef: fixture.candidateRef,
    context: APP_CONTEXT,
    fetchRemote: fixture.remote,
    pushRemote: fixture.remote,
    releasePreflight: async () => ({
      packageName: '@1f4bcai/agent',
      version: '0.1.4',
      tag: 'agent-v0.1.4',
      mode: 'prepare' as const,
    }),
    allowTestRemote: true,
    releaseAppToken: 'test-release-app-token-1234567890',
    candidateCiCheck: async () => ({
      runId: 412,
      runAttempt: 1,
      candidateCommit: fixture.candidate,
      candidateRef: fixture.candidateRef,
    }),
  }
}

afterEach(async () => {
  for (const path of cleanup.splice(0)) {
    await rm(path, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 })
  }
})

describe('App-only public release candidate promotion', () => {
  it('rejects every non-App or non-dispatch execution context', () => {
    expect(() => assertReleaseAppContext(APP_CONTEXT)).not.toThrow()
    for (const field of [
      'repository',
      'eventName',
      'actor',
      'actorId',
      'triggeringActor',
      'expectedActor',
      'expectedActorId',
    ] as const) {
      expect(() => assertReleaseAppContext({ ...APP_CONTEXT, [field]: '' }))
        .toThrow(/release App promotion context/i)
    }
    expect(() => assertReleaseAppContext({
      ...APP_CONTEXT,
      triggeringActor: 'human-maintainer',
    })).toThrow(/release App promotion context/i)
  })

  it('requires one successful exact-SHA candidate CI run', () => {
    const expected = {
      candidateCommit: 'a'.repeat(40),
      candidateRef: `agent-candidate-0.1.4-${'a'.repeat(12)}`,
      expectedActor: APP_CONTEXT.expectedActor,
      expectedActorId: APP_CONTEXT.expectedActorId,
    }
    const successful = {
      id: 412,
      run_attempt: 1,
      name: 'Public agent CLI CI',
      event: 'push',
      status: 'completed',
      conclusion: 'success',
      head_sha: expected.candidateCommit,
      head_branch: expected.candidateRef,
      path: '.github/workflows/agent-cli-public-ci.yml',
      actor: { login: expected.expectedActor, id: Number(expected.expectedActorId) },
      triggering_actor: { login: expected.expectedActor, id: Number(expected.expectedActorId) },
      repository: { full_name: '1f4bcai/1f4bc-agent' },
      head_repository: { full_name: '1f4bcai/1f4bc-agent' },
    }
    expect(assertSuccessfulCandidateCi({ workflow_runs: [successful] }, expected)).toEqual({
      runId: 412,
      runAttempt: 1,
      candidateCommit: expected.candidateCommit,
      candidateRef: expected.candidateRef,
    })

    for (const workflowRuns of [
      [],
      [{ ...successful, head_sha: 'b'.repeat(40) }],
      [{ ...successful, status: 'in_progress', conclusion: null }],
      [{ ...successful, conclusion: 'failure' }],
    ]) {
      expect(() => assertSuccessfulCandidateCi({ workflow_runs: workflowRuns }, expected))
        .toThrow(/successful exact-SHA public candidate CI/i)
    }
  })

  it('never advances main when the exact candidate CI gate fails', async () => {
    const fixture = await promotionFixture()
    await expect(promoteReleaseCandidate({
      ...options(fixture),
      candidateCiCheck: async () => {
        throw new Error('successful exact-SHA public candidate CI is required')
      },
    })).rejects.toThrow(/successful exact-SHA public candidate CI/i)
    expect((await git(fixture.remote, ['rev-parse', 'refs/heads/main'])).stdout.trim())
      .toBe(fixture.base)
    expect((await git(fixture.remote, ['rev-parse', `refs/heads/${fixture.candidateRef}`])).stdout.trim())
      .toBe(fixture.candidate)
  }, 30_000)

  it('verifies from old main, then atomically fast-forwards main and deletes the candidate', async () => {
    const fixture = await promotionFixture()
    const result = await promoteReleaseCandidate(options(fixture))
    expect(result).toMatchObject({
      baseCommit: fixture.base,
      candidateCommit: fixture.candidate,
      candidateRef: fixture.candidateRef,
      version: '0.1.4',
      promoted: true,
      shallowCandidate: true,
    })
    const refs = (await git(fixture.remote, [
      'for-each-ref', '--format=%(refname) %(objectname)', 'refs/heads',
    ])).stdout
    expect(refs).toContain(`refs/heads/main ${fixture.candidate}`)
    expect(refs).not.toContain(fixture.candidateRef)
  }, 30_000)

  it('rejects a candidate whose raw parent is not the live canonical main', async () => {
    const fixture = await promotionFixture({ extraParent: true })
    await expect(promoteReleaseCandidate(options(fixture))).rejects.toThrow(/exact linear parent/i)
    expect((await git(fixture.remote, ['rev-parse', 'refs/heads/main'])).stdout.trim())
      .toBe(fixture.base)
  }, 30_000)

  it('rejects a candidate that changes pinned release authority', async () => {
    const fixture = await promotionFixture({ alterAuthority: true })
    await expect(promoteReleaseCandidate(options(fixture))).rejects.toThrow(/pinned release authority/i)
    expect((await git(fixture.remote, ['rev-parse', 'refs/heads/main'])).stdout.trim())
      .toBe(fixture.base)
  }, 30_000)

  it('uses an atomic candidate lease so a ref race cannot partially advance main', async () => {
    const fixture = await promotionFixture()
    const promoted = options(fixture)
    await expect(promoteReleaseCandidate({
      ...promoted,
      hooks: {
        beforePush: async () => {
          await git(fixture.source, [
            'push', '--force', 'origin', `${fixture.base}:refs/heads/${fixture.candidateRef}`,
          ])
        },
      },
    })).rejects.toThrow(/atomic promotion failed/i)
    expect((await git(fixture.remote, ['rev-parse', 'refs/heads/main'])).stdout.trim())
      .toBe(fixture.base)
    expect((await git(fixture.remote, ['rev-parse', `refs/heads/${fixture.candidateRef}`])).stdout.trim())
      .toBe(fixture.base)
  }, 30_000)

  it('uses an atomic main lease so a main race cannot delete the candidate', async () => {
    const fixture = await promotionFixture()
    await git(fixture.source, ['switch', 'main'])
    await git(fixture.source, ['commit', '--allow-empty', '-m', 'raced main'], {
      GIT_AUTHOR_DATE: '2026-08-25T00:01:30Z',
      GIT_COMMITTER_DATE: '2026-08-25T00:01:30Z',
    })
    const racedMain = (await git(fixture.source, ['rev-parse', 'HEAD'])).stdout.trim()
    const promoted = options(fixture)
    await expect(promoteReleaseCandidate({
      ...promoted,
      hooks: {
        beforePush: async () => {
          await git(fixture.source, ['push', '--force', 'origin', 'HEAD:refs/heads/main'])
        },
      },
    })).rejects.toThrow(/atomic promotion failed/i)
    expect((await git(fixture.remote, ['rev-parse', 'refs/heads/main'])).stdout.trim())
      .toBe(racedMain)
    expect((await git(fixture.remote, ['rev-parse', `refs/heads/${fixture.candidateRef}`])).stdout.trim())
      .toBe(fixture.candidate)
  }, 30_000)

  it('rejects unexpected and racing public refs without advancing main', async () => {
    const unexpected = await promotionFixture()
    await git(unexpected.source, ['tag', 'not-a-release', unexpected.base])
    await git(unexpected.source, ['push', 'origin', 'not-a-release'])
    await expect(promoteReleaseCandidate(options(unexpected))).rejects.toThrow(/public ref/i)
    expect((await git(unexpected.remote, ['rev-parse', 'refs/heads/main'])).stdout.trim())
      .toBe(unexpected.base)

    const raced = await promotionFixture()
    await expect(promoteReleaseCandidate({
      ...options(raced),
      hooks: {
        beforeRefCheck: async () => {
          await git(raced.source, ['tag', 'agent-v9.9.9', raced.base])
          await git(raced.source, ['push', 'origin', 'agent-v9.9.9'])
        },
      },
    })).rejects.toThrow(/public ref|changed/i)
    expect((await git(raced.remote, ['rev-parse', 'refs/heads/main'])).stdout.trim())
      .toBe(raced.base)
  }, 30_000)

  it('leases existing release tags atomically and verifies the complete post-push ref set', async () => {
    const racedTag = await promotionFixture()
    await expect(promoteReleaseCandidate({
      ...options(racedTag),
      hooks: {
        beforePush: async () => {
          await git(racedTag.source, [
            'push', '--force', 'origin', `${racedTag.candidate}:refs/tags/agent-v0.1.3`,
          ])
        },
      },
    })).rejects.toThrow(/atomic promotion failed/i)
    expect((await git(racedTag.remote, ['rev-parse', 'refs/heads/main'])).stdout.trim())
      .toBe(racedTag.base)

    const postPush = await promotionFixture()
    await expect(promoteReleaseCandidate({
      ...options(postPush),
      hooks: {
        afterPush: async () => {
          await git(postPush.source, ['tag', 'post-push-surprise', postPush.candidate])
          await git(postPush.source, ['push', 'origin', 'post-push-surprise'])
        },
      },
    })).rejects.toThrow(/complete public ref set/i)
    expect((await git(postPush.remote, ['rev-parse', 'refs/heads/main'])).stdout.trim())
      .toBe(postPush.candidate)
  }, 30_000)

  it('fails closed on a missing or malformed App token without disclosing it', async () => {
    const fixture = await promotionFixture()
    for (const releaseAppToken of [undefined, 'short', 'invalid token value']) {
      let failure: unknown
      try {
        await promoteReleaseCandidate({ ...options(fixture), releaseAppToken })
      } catch (error) {
        failure = error
      }
      expect(failure).toBeInstanceOf(Error)
      expect(String(failure)).toMatch(/release App token is missing or invalid/i)
      if (releaseAppToken) expect(String(failure)).not.toContain(releaseAppToken)
    }
  }, 30_000)
})
