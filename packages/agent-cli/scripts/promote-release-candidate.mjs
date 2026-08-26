import { execFile } from 'node:child_process'
import { chmod, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import { releasePreflight as defaultReleasePreflight } from './release-preflight.mjs'
import { verifyPublicTree } from './verify-public-tree.mjs'

const execFileAsync = promisify(execFile)
const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const repositoryRoot = resolve(packageRoot, '..', '..')
const TRUSTED_REPOSITORY = '1f4bcai/1f4bc-agent'
const TRUSTED_REMOTE = `https://github.com/${TRUSTED_REPOSITORY}.git`
const PUBLIC_GIT_NAME = '1F4BC Release'
const PUBLIC_GIT_EMAIL = 'support@1f4bc.com'
const RELEASE_MESSAGE_PREFIX = 'release: publish @1f4bcai/agent@'
const PUBLIC_CI_NAME = 'Public agent CLI CI'
const PUBLIC_CI_WORKFLOW_PATH = '.github/workflows/agent-cli-public-ci.yml'
const PUBLIC_CI_WORKFLOW_ID = 'agent-cli-public-ci.yml'
const STABLE_SEMVER = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/
const RELEASE_TAG_REF = /^refs\/tags\/agent-v((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))$/
const FULL_SHA = /^[0-9a-f]{40}$/
const MAX_JSON_BYTES = 1024 * 1024
const PINNED_AUTHORITY_PATHS = Object.freeze([
  '.github/workflows',
  'packages/agent-cli/scripts',
])

function cleanGitEnvironment(extra = {}) {
  const env = {}
  for (const [key, value] of Object.entries(process.env)) {
    if (
      !key.startsWith('GIT_') &&
      key !== 'RELEASE_APP_TOKEN' &&
      !key.endsWith('_PRIVATE_KEY') &&
      value !== undefined
    ) env[key] = value
  }
  return {
    ...env,
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_NO_REPLACE_OBJECTS: '1',
    GIT_NO_LAZY_FETCH: '1',
    GIT_ATTR_NOSYSTEM: '1',
    GIT_TERMINAL_PROMPT: '0',
    GIT_PAGER: 'cat',
    ...extra,
  }
}

async function git(repository, args, options = {}) {
  const { label = 'release candidate Git command', env, ...execOptions } = options
  try {
    return await execFileAsync('git', [
      '-c', 'core.fsmonitor=false',
      '-c', 'diff.orderFile=/dev/null',
      '-c', 'log.mailmap=false',
      '-c', 'log.showSignature=false',
      '-C', repository,
      ...args,
    ], {
      encoding: 'utf8',
      maxBuffer: 8 * 1024 * 1024,
      ...execOptions,
      env: cleanGitEnvironment(env),
    })
  } catch (error) {
    throw new Error(`${label} failed`, { cause: error })
  }
}

function exactSha(value, label) {
  if (!FULL_SHA.test(value ?? '')) throw new Error(`${label} must be a full lowercase Git SHA`)
  return value
}

function compareStableVersions(left, right) {
  const leftParts = left.split('.').map((part) => BigInt(part))
  const rightParts = right.split('.').map((part) => BigInt(part))
  for (let index = 0; index < 3; index += 1) {
    if (leftParts[index] < rightParts[index]) return -1
    if (leftParts[index] > rightParts[index]) return 1
  }
  return 0
}

export function assertReleaseAppContext(context) {
  const valid =
    context?.repository === TRUSTED_REPOSITORY &&
    context?.eventName === 'repository_dispatch' &&
    typeof context?.expectedActor === 'string' && context.expectedActor.length > 0 &&
    typeof context?.expectedActorId === 'string' && /^[1-9][0-9]*$/.test(context.expectedActorId) &&
    context.actor === context.expectedActor &&
    context.actorId === context.expectedActorId &&
    context.triggeringActor === context.expectedActor
  if (!valid) throw new Error('release App promotion context is not authorized')
}

function validRunActor(actor, expectedActor, expectedActorId) {
  return actor?.login === expectedActor && String(actor?.id ?? '') === expectedActorId
}

export function assertSuccessfulCandidateCi(payload, expected) {
  if (!payload || typeof payload !== 'object' || !Array.isArray(payload.workflow_runs)) {
    throw new Error('successful exact-SHA public candidate CI is required')
  }
  const successful = payload.workflow_runs.filter((run) =>
    run && typeof run === 'object' &&
    Number.isSafeInteger(run.id) && run.id > 0 &&
    Number.isSafeInteger(run.run_attempt) && run.run_attempt > 0 &&
    run.name === PUBLIC_CI_NAME &&
    run.path === PUBLIC_CI_WORKFLOW_PATH &&
    run.event === 'push' &&
    run.status === 'completed' &&
    run.conclusion === 'success' &&
    run.head_sha === expected.candidateCommit &&
    run.head_branch === expected.candidateRef &&
    run.repository?.full_name === TRUSTED_REPOSITORY &&
    run.head_repository?.full_name === TRUSTED_REPOSITORY &&
    validRunActor(run.actor, expected.expectedActor, expected.expectedActorId) &&
    validRunActor(run.triggering_actor, expected.expectedActor, expected.expectedActorId)
  )
  if (successful.length === 0) {
    throw new Error('successful exact-SHA public candidate CI is required')
  }
  successful.sort((left, right) => right.id - left.id)
  const run = successful[0]
  return {
    runId: run.id,
    runAttempt: run.run_attempt,
    candidateCommit: expected.candidateCommit,
    candidateRef: expected.candidateRef,
  }
}

async function requireSuccessfulCandidateCi({
  candidateCommit,
  candidateRef,
  expectedActor,
  expectedActorId,
  fetcher = fetch,
}) {
  const url = new URL(
    `https://api.github.com/repos/${TRUSTED_REPOSITORY}/actions/workflows/${PUBLIC_CI_WORKFLOW_ID}/runs`,
  )
  url.searchParams.set('branch', candidateRef)
  url.searchParams.set('event', 'push')
  url.searchParams.set('per_page', '10')
  let response
  try {
    response = await fetcher(url, {
      headers: {
        Accept: 'application/vnd.github+json',
        'User-Agent': '1f4bc-agent-release-candidate-verifier',
        'X-GitHub-Api-Version': '2022-11-28',
      },
      redirect: 'error',
    })
  } catch {
    throw new Error('successful exact-SHA public candidate CI could not be verified')
  }
  const declaredLength = Number(response.headers?.get?.('content-length') ?? 0)
  if (!response.ok || (declaredLength > 0 && declaredLength > MAX_JSON_BYTES)) {
    throw new Error('successful exact-SHA public candidate CI could not be verified')
  }
  const text = await response.text()
  if (Buffer.byteLength(text) > MAX_JSON_BYTES) {
    throw new Error('successful exact-SHA public candidate CI could not be verified')
  }
  let payload
  try {
    payload = JSON.parse(text)
  } catch {
    throw new Error('successful exact-SHA public candidate CI could not be verified')
  }
  return assertSuccessfulCandidateCi(payload, {
    candidateCommit,
    candidateRef,
    expectedActor,
    expectedActorId,
  })
}

function assertReleaseAppToken(token) {
  if (
    typeof token !== 'string' ||
    token.length < 20 ||
    token.length > 1024 ||
    /[\x00-\x20\x7f]/.test(token)
  ) {
    throw new Error('ephemeral release App token is missing or invalid')
  }
  return token
}

function assertCandidateRef(candidateRef) {
  if (!/^agent-candidate-(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)-[0-9a-f]{12}$/.test(candidateRef ?? '')) {
    throw new Error('release candidate ref is invalid')
  }
  return candidateRef
}

const GITHUB_MANAGED_PULL_REF = /^refs\/pull\/[1-9][0-9]*\/(?:head|merge)$/
function parseDirectPublicRefs(output) {
  const refs = new Map()
  for (const line of output.split('\n').filter(Boolean)) {
    const match = /^([0-9a-f]{40})\t(refs\/.+)$/.exec(line)
    if (!match) throw new Error('canonical remote returned malformed public refs')
    if (GITHUB_MANAGED_PULL_REF.test(match[2])) continue
    if (refs.has(match[2])) throw new Error('canonical remote returned malformed public refs')
    refs.set(match[2], match[1])
  }
  return refs
}

function assertCandidateRefSet(refs, candidateRef, mainCommit, candidateCommit) {
  const permittedHeads = new Map([
    ['refs/heads/main', mainCommit],
    [`refs/heads/${candidateRef}`, candidateCommit],
  ])
  const heads = [...refs].filter(([ref]) => ref.startsWith('refs/heads/'))
  if (
    heads.length !== permittedHeads.size ||
    [...permittedHeads].some(([ref, commit]) => refs.get(ref) !== commit) ||
    [...refs.keys()].some((ref) =>
      !permittedHeads.has(ref) && !RELEASE_TAG_REF.test(ref)
    )
  ) {
    throw new Error('canonical remote public ref set is not exactly permitted')
  }
  return refs
}

function sameRefSet(left, right) {
  return left.size === right.size && [...left].every(([ref, commit]) => right.get(ref) === commit)
}

function containsRefSet(actual, expected) {
  return [...expected].every(([ref, commit]) => actual.get(ref) === commit)
}

async function remotePublicRefs(
  repository, remote, candidateRef, mainCommit, candidateCommit,
) {
  const { stdout } = await git(repository, ['ls-remote', '--refs', remote], {
    label: 'complete canonical public ref inspection',
  })
  return assertCandidateRefSet(
    parseDirectPublicRefs(stdout), candidateRef, mainCommit, candidateCommit,
  )
}

async function readJsonFile(path, label) {
  const bytes = await readFile(path)
  if (bytes.byteLength > MAX_JSON_BYTES || bytes.includes(0)) {
    throw new Error(`${label} is invalid`)
  }
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
  } catch {
    throw new Error(`${label} is invalid`)
  }
}

async function jsonAt(repository, commit, path, label) {
  const { stdout } = await git(repository, ['show', `${commit}:${path}`], {
    label: `${label} inspection`,
    maxBuffer: MAX_JSON_BYTES,
  })
  if (Buffer.byteLength(stdout) > MAX_JSON_BYTES) throw new Error(`${label} is invalid`)
  try {
    return JSON.parse(stdout)
  } catch {
    throw new Error(`${label} is invalid`)
  }
}

function releaseCoordinates(root, manifest, lock, label) {
  const version = manifest?.version
  if (
    manifest?.name !== '@1f4bcai/agent' ||
    !STABLE_SEMVER.test(version ?? '') ||
    manifest?.repository?.url !== `git+https://github.com/${TRUSTED_REPOSITORY}.git` ||
    root?.name !== '1f4bc-agent-release-source' ||
    root?.version !== version ||
    root?.private !== true ||
    root?.type !== 'module' ||
    JSON.stringify(root?.workspaces) !== JSON.stringify(['packages/agent-cli']) ||
    lock?.version !== version ||
    lock?.packages?.['']?.version !== version ||
    lock?.packages?.['packages/agent-cli']?.version !== version
  ) {
    throw new Error(`${label} release identity is invalid`)
  }
  return version
}

async function candidateVersion(repository, baseCommit) {
  const [root, manifest, lock, baseRoot, baseManifest, baseLock] = await Promise.all([
    readJsonFile(join(repository, 'package.json'), 'candidate root manifest'),
    readJsonFile(join(repository, 'packages/agent-cli/package.json'), 'candidate package manifest'),
    readJsonFile(join(repository, 'package-lock.json'), 'candidate lock'),
    jsonAt(repository, baseCommit, 'package.json', 'base root manifest'),
    jsonAt(repository, baseCommit, 'packages/agent-cli/package.json', 'base package manifest'),
    jsonAt(repository, baseCommit, 'package-lock.json', 'base lock'),
  ])
  const version = releaseCoordinates(root, manifest, lock, 'candidate')
  const baseVersion = releaseCoordinates(baseRoot, baseManifest, baseLock, 'base')
  if (compareStableVersions(baseVersion, version) >= 0) {
    throw new Error('release candidate version must increase strictly from canonical main')
  }
  return { version, baseVersion, manifest }
}

async function assertPermittedReleaseTags(
  repository, refs, baseVersion, baseCommit, candidateVersionValue,
) {
  const tags = [...refs].filter(([ref]) => ref.startsWith('refs/tags/'))
  if (!refs.has(`refs/tags/agent-v${baseVersion}`)) {
    throw new Error('canonical base release tag is missing')
  }
  if (refs.has(`refs/tags/agent-v${candidateVersionValue}`)) {
    throw new Error('release candidate version already has a public tag')
  }
  for (const [ref, expectedCommit] of tags) {
    const match = RELEASE_TAG_REF.exec(ref)
    if (!match || compareStableVersions(match[1], baseVersion) > 0) {
      throw new Error('canonical remote contains an unpermitted release tag')
    }
    const objectType = (await git(repository, ['cat-file', '-t', ref], {
      label: 'canonical release tag type inspection',
    })).stdout.trim()
    const resolved = (await git(repository, ['rev-parse', '--verify', `${ref}^{commit}`], {
      label: 'canonical release tag resolution',
    })).stdout.trim()
    if (objectType !== 'commit' || resolved !== expectedCommit) {
      throw new Error('canonical release tag is not the exact lightweight commit ref')
    }
    const [root, manifest, lock] = await Promise.all([
      jsonAt(repository, expectedCommit, 'package.json', 'tag root manifest'),
      jsonAt(repository, expectedCommit, 'packages/agent-cli/package.json', 'tag package manifest'),
      jsonAt(repository, expectedCommit, 'package-lock.json', 'tag lock'),
    ])
    if (releaseCoordinates(root, manifest, lock, 'tag') !== match[1]) {
      throw new Error('canonical release tag version differs from its package tree')
    }
    const rawCommit = (await git(repository, ['cat-file', 'commit', expectedCommit], {
      label: 'canonical release tag commit inspection',
    })).stdout
    const messageBoundary = rawCommit.indexOf('\n\n')
    if (
      messageBoundary < 0 ||
      rawCommit.slice(messageBoundary + 2) !== `${RELEASE_MESSAGE_PREFIX}${match[1]}\n`
    ) {
      throw new Error('canonical release tag does not target an exact release commit')
    }
    try {
      await git(repository, ['merge-base', '--is-ancestor', expectedCommit, baseCommit], {
        label: 'canonical release tag ancestry inspection',
      })
    } catch {
      throw new Error('canonical release tag is not an ancestor of main')
    }
  }
}

async function assertRawCandidateCommit(repository, candidateCommit, baseCommit, version) {
  const { stdout } = await git(repository, ['cat-file', 'commit', candidateCommit], {
    label: 'raw release candidate commit inspection',
  })
  const boundary = stdout.indexOf('\n\n')
  if (boundary < 0) throw new Error('release candidate commit metadata is invalid')
  const headers = stdout.slice(0, boundary).split('\n')
  const body = stdout.slice(boundary + 2)
  const expectedIdentity = `${PUBLIC_GIT_NAME} <${PUBLIC_GIT_EMAIL}>`
  const tree = headers[0]
  const parent = headers[1]
  const author = headers[2]
  const committer = headers[3]
  const authorMatch = new RegExp(
    `^author ${expectedIdentity.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')} (0|[1-9][0-9]*) \\+0000$`,
  ).exec(author ?? '')
  const committerMatch = new RegExp(
    `^committer ${expectedIdentity.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')} (0|[1-9][0-9]*) \\+0000$`,
  ).exec(committer ?? '')
  if (
    headers.length !== 4 ||
    !/^tree [0-9a-f]{40}$/.test(tree ?? '') ||
    parent !== `parent ${baseCommit}` ||
    !authorMatch ||
    !committerMatch ||
    authorMatch[1] !== committerMatch[1]
  ) {
    throw new Error('release candidate must have the exact linear parent and organization identity')
  }
  if (body !== `${RELEASE_MESSAGE_PREFIX}${version}\n`) {
    throw new Error('release candidate commit message does not match its version')
  }
}

async function assertPinnedAuthorityUnchanged(repository, baseCommit, candidateCommit) {
  const { stdout } = await git(repository, [
    'diff', '--name-only', '--no-renames', baseCommit, candidateCommit, '--',
    ...PINNED_AUTHORITY_PATHS,
  ], { label: 'pinned release authority comparison' })
  if (stdout.trim() !== '') {
    throw new Error('release candidate changes pinned release authority')
  }
}

async function configureCandidateCheckout(repository) {
  for (const [key, value] of [
    ['maintenance.auto', 'false'],
    ['gc.auto', '0'],
    ['user.name', PUBLIC_GIT_NAME],
    ['user.email', PUBLIC_GIT_EMAIL],
  ]) {
    await git(repository, ['config', key, value], { label: 'candidate checkout configuration' })
  }
  await git(repository, ['remote', 'add', 'origin', TRUSTED_REMOTE], {
    label: 'candidate checkout remote configuration',
  })
}

async function createCandidateCheckout(
  root, fetchRemote, baseCommit, candidateCommit, candidateRef, publicRefs,
) {
  const repository = join(root, 'candidate')
  await git(root, ['init', '-b', 'main', repository], { label: 'candidate checkout initialization' })
  await configureCandidateCheckout(repository)
  await git(repository, [
    'fetch', '--no-tags', '--depth=1', fetchRemote,
    `+refs/heads/main:refs/remotes/origin/main`,
  ], { label: 'canonical main shallow fetch' })
  await git(repository, [
    'fetch', '--no-tags', '--depth=1', fetchRemote,
    `+refs/heads/${candidateRef}:refs/remotes/origin/${candidateRef}`,
  ], { label: 'release candidate shallow fetch' })
  for (const ref of [...publicRefs.keys()].filter((value) => value.startsWith('refs/tags/')).sort()) {
    await git(repository, [
      'fetch', '--no-tags', '--depth=1', fetchRemote, `+${ref}:${ref}`,
    ], { label: 'canonical release tag shallow fetch' })
  }
  const resolvedBase = (await git(repository, [
    'rev-parse', '--verify', 'refs/remotes/origin/main^{commit}',
  ], { label: 'shallow canonical main resolution' })).stdout.trim()
  const resolvedCandidate = (await git(repository, [
    'rev-parse', '--verify', `refs/remotes/origin/${candidateRef}^{commit}`,
  ], { label: 'shallow release candidate resolution' })).stdout.trim()
  if (resolvedBase !== baseCommit || resolvedCandidate !== candidateCommit) {
    throw new Error('shallow checkout refs differ from the prechecked release coordinates')
  }
  await git(repository, ['checkout', '--detach', candidateCommit], {
    label: 'release candidate checkout',
  })
  const shallow = (await git(repository, ['rev-parse', '--is-shallow-repository'], {
    label: 'candidate shallow-check verification',
  })).stdout.trim()
  if (shallow !== 'true') throw new Error('release candidate checkout must remain shallow')
  return repository
}

async function createPublicHistoryCheckout(
  root, fetchRemote, baseCommit, publicRefs,
) {
  const repository = join(root, 'history')
  await git(root, ['init', '-b', 'main', repository], {
    label: 'canonical release history checkout initialization',
  })
  await configureCandidateCheckout(repository)
  await git(repository, [
    'fetch', '--no-tags', fetchRemote,
    '+refs/heads/main:refs/remotes/origin/main',
  ], { label: 'complete canonical main history fetch' })
  for (const ref of [...publicRefs.keys()].filter((value) => value.startsWith('refs/tags/')).sort()) {
    await git(repository, [
      'fetch', '--no-tags', fetchRemote, `+${ref}:${ref}`,
    ], { label: 'complete canonical release tag fetch' })
  }
  const resolvedBase = (await git(repository, [
    'rev-parse', '--verify', 'refs/remotes/origin/main^{commit}',
  ], { label: 'complete canonical main resolution' })).stdout.trim()
  if (resolvedBase !== baseCommit) {
    throw new Error('complete canonical history differs from the prechecked main')
  }
  await git(repository, ['checkout', '-B', 'main', baseCommit], {
    label: 'complete canonical main checkout',
  })
  const shallow = (await git(repository, ['rev-parse', '--is-shallow-repository'], {
    label: 'canonical release history completeness check',
  })).stdout.trim()
  if (shallow !== 'false') throw new Error('canonical release history must be complete')
  return repository
}

async function assertAuthorityCheckout(authorityRoot, baseCommit, fetchRemote, allowTestRemote) {
  const root = await realpath(resolve(authorityRoot))
  const status = (await git(root, ['status', '--porcelain=v1', '--untracked-files=all'], {
    label: 'release authority cleanliness check',
  })).stdout
  if (status !== '') throw new Error('release authority checkout must be clean')
  const head = (await git(root, ['rev-parse', '--verify', 'HEAD^{commit}'], {
    label: 'release authority HEAD resolution',
  })).stdout.trim()
  if (head !== baseCommit) throw new Error('release authority is not pinned to canonical main')
  if (!allowTestRemote) {
    const origin = (await git(root, ['remote', 'get-url', 'origin'], {
      label: 'release authority remote inspection',
    })).stdout.trim()
    if (origin !== TRUSTED_REMOTE && origin !== TRUSTED_REMOTE.slice(0, -4)) {
      throw new Error('release authority checkout is not canonical')
    }
    if (fetchRemote !== TRUSTED_REMOTE) throw new Error('release candidate remote is not canonical')
  }
  return root
}

async function writeAskpass(root) {
  const path = join(root, 'askpass.sh')
  await writeFile(path, [
    '#!/bin/sh',
    'case "$1" in',
    '  *Username*) printf %s x-access-token ;;',
    '  *Password*) printf %s "$RELEASE_APP_TOKEN" ;;',
    '  *) exit 1 ;;',
    'esac',
    '',
  ].join('\n'), { mode: 0o700, flag: 'wx' })
  await chmod(path, 0o700)
  return path
}

export async function promoteReleaseCandidate(options) {
  const {
    mode = 'promote',
    authorityRoot = repositoryRoot,
    baseCommit: rawBaseCommit,
    candidateCommit: rawCandidateCommit,
    candidateRef: rawCandidateRef,
    context,
    fetchRemote = TRUSTED_REMOTE,
    pushRemote = TRUSTED_REMOTE,
    releasePreflight = defaultReleasePreflight,
    candidateCiCheck = requireSuccessfulCandidateCi,
    publicHistoryCheck = verifyPublicTree,
    allowTestRemote = false,
    releaseAppToken,
    hooks = {},
  } = options ?? {}
  if (mode !== 'verify' && mode !== 'promote') throw new Error('candidate mode must be verify or promote')
  assertReleaseAppContext(context)
  if (!allowTestRemote && publicHistoryCheck !== verifyPublicTree) {
    throw new Error('production public history verification cannot be overridden')
  }
  if (mode === 'promote') assertReleaseAppToken(releaseAppToken)
  const baseCommit = exactSha(rawBaseCommit, 'canonical main')
  const candidateCommit = exactSha(rawCandidateCommit, 'release candidate')
  if (baseCommit === candidateCommit) throw new Error('release candidate must differ from canonical main')
  const candidateRef = assertCandidateRef(rawCandidateRef)
  const authority = await assertAuthorityCheckout(
    authorityRoot, baseCommit, fetchRemote, allowTestRemote,
  )
  if (!allowTestRemote && pushRemote !== TRUSTED_REMOTE) {
    throw new Error('release candidate push remote is not canonical')
  }
  const initialRefs = await remotePublicRefs(
    authority, fetchRemote, candidateRef, baseCommit, candidateCommit,
  )
  if (
    initialRefs.get('refs/heads/main') !== baseCommit ||
    initialRefs.get(`refs/heads/${candidateRef}`) !== candidateCommit
  ) {
    throw new Error('live canonical refs differ from the prechecked release coordinates')
  }

  const temporary = await mkdtemp(join(tmpdir(), '1f4bc-agent-candidate-'))
  try {
    await chmod(temporary, 0o700)
    const candidate = await createCandidateCheckout(
      temporary, fetchRemote, baseCommit, candidateCommit, candidateRef, initialRefs,
    )
    const publicHistory = await createPublicHistoryCheckout(
      temporary, fetchRemote, baseCommit, initialRefs,
    )
    const { version, baseVersion, manifest } = await candidateVersion(candidate, baseCommit)
    if (candidateRef !== `agent-candidate-${version}-${candidateCommit.slice(0, 12)}`) {
      throw new Error('release candidate ref does not match its version and commit')
    }
    await assertRawCandidateCommit(candidate, candidateCommit, baseCommit, version)
    await assertPinnedAuthorityUnchanged(candidate, baseCommit, candidateCommit)
    await publicHistoryCheck(publicHistory)
    await assertPermittedReleaseTags(
      publicHistory, initialRefs, baseVersion, baseCommit, version,
    )
    await verifyPublicTree(candidate, { mode: 'snapshot-only' })
    await candidateCiCheck({
      candidateCommit,
      candidateRef,
      expectedActor: context.expectedActor,
      expectedActorId: context.expectedActorId,
    })
    await releasePreflight({
      mode: 'prepare',
      manifest,
      cwd: candidate,
    })

    const verified = {
      baseCommit,
      candidateCommit,
      candidateRef,
      version,
      shallowCandidate: true,
      promoted: false,
    }
    if (mode === 'verify') return verified

    await hooks.beforeRefCheck?.()
    const beforePush = await remotePublicRefs(
      authority, fetchRemote, candidateRef, baseCommit, candidateCommit,
    )
    if (
      !sameRefSet(initialRefs, beforePush)
    ) {
      throw new Error('canonical public ref set changed after release candidate verification')
    }
    await hooks.beforePush?.()
    const askpass = allowTestRemote ? undefined : await writeAskpass(temporary)
    const releaseTags = [...initialRefs]
      .filter(([ref]) => ref.startsWith('refs/tags/'))
      .sort(([left], [right]) => left.localeCompare(right))
    await git(candidate, [
      'push', '--atomic', '--porcelain',
      `--force-with-lease=refs/heads/main:${baseCommit}`,
      `--force-with-lease=refs/heads/${candidateRef}:${candidateCommit}`,
      ...releaseTags.map(([ref, commit]) => `--force-with-lease=${ref}:${commit}`),
      pushRemote,
      `${candidateCommit}:refs/heads/main`,
      `:refs/heads/${candidateRef}`,
      ...releaseTags.map(([ref, commit]) => `${commit}:${ref}`),
    ], {
      label: 'atomic promotion',
      env: allowTestRemote ? {} : {
        GIT_ASKPASS: askpass,
        RELEASE_APP_TOKEN: releaseAppToken,
      },
    })
    await hooks.afterPush?.()
    const expectedFinalRefs = new Map(initialRefs)
    expectedFinalRefs.set('refs/heads/main', candidateCommit)
    expectedFinalRefs.delete(`refs/heads/${candidateRef}`)
    let postconditionOk = false
    try {
      const finalOutput = (await git(authority, ['ls-remote', '--refs', fetchRemote], {
        label: 'promoted complete public ref confirmation',
      })).stdout
      postconditionOk = sameRefSet(parseDirectPublicRefs(finalOutput), expectedFinalRefs)
    } catch {
      postconditionOk = false
    }
    if (!postconditionOk) {
      let rollbackConfirmed = false
      try {
        await git(candidate, [
          'push', '--atomic', '--porcelain',
          `--force-with-lease=refs/heads/main:${candidateCommit}`,
          `--force-with-lease=refs/heads/${candidateRef}:`,
          ...releaseTags.map(([ref, commit]) => `--force-with-lease=${ref}:${commit}`),
          pushRemote,
          `${baseCommit}:refs/heads/main`,
          `${candidateCommit}:refs/heads/${candidateRef}`,
          ...releaseTags.map(([ref, commit]) => `${commit}:${ref}`),
        ], {
          label: 'lease-protected promotion rollback',
          env: allowTestRemote ? {} : {
            GIT_ASKPASS: askpass,
            RELEASE_APP_TOKEN: releaseAppToken,
          },
        })
        const rollbackOutput = (await git(authority, ['ls-remote', '--refs', fetchRemote], {
          label: 'rolled-back complete public ref confirmation',
        })).stdout
        rollbackConfirmed = containsRefSet(parseDirectPublicRefs(rollbackOutput), initialRefs)
      } catch {
        rollbackConfirmed = false
      }
      if (!rollbackConfirmed) {
        throw new Error('atomic promotion postcondition failed and rollback could not be confirmed')
      }
      throw new Error('atomic promotion postcondition failed; verified refs were rolled back')
    }
    return { ...verified, promoted: true }
  } finally {
    await rm(temporary, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 })
  }
}

function parseArguments(argv) {
  const mode = argv[0]
  if (mode !== 'verify' && mode !== 'promote') {
    throw new Error('usage: promote-release-candidate <verify|promote> --base-sha SHA --candidate-sha SHA --candidate-ref REF')
  }
  const values = new Map()
  for (let index = 1; index < argv.length; index += 2) {
    const key = argv[index]
    const value = argv[index + 1]
    if (!key?.startsWith('--') || value === undefined || values.has(key)) {
      throw new Error('invalid release candidate arguments')
    }
    values.set(key, value)
  }
  if (values.size !== 3) throw new Error('invalid release candidate arguments')
  return {
    mode,
    baseCommit: values.get('--base-sha'),
    candidateCommit: values.get('--candidate-sha'),
    candidateRef: values.get('--candidate-ref'),
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const token = process.env.RELEASE_APP_TOKEN
  delete process.env.RELEASE_APP_TOKEN
  const parsed = parseArguments(process.argv.slice(2))
  const result = await promoteReleaseCandidate({
    ...parsed,
    context: {
      repository: process.env.GITHUB_REPOSITORY,
      eventName: process.env.GITHUB_EVENT_NAME,
      actor: process.env.GITHUB_ACTOR,
      actorId: process.env.GITHUB_ACTOR_ID,
      triggeringActor: process.env.GITHUB_TRIGGERING_ACTOR,
      expectedActor: process.env.EXPECTED_RELEASE_APP_ACTOR,
      expectedActorId: process.env.EXPECTED_RELEASE_APP_ACTOR_ID,
    },
    releaseAppToken: token,
  })
  process.stdout.write(`${JSON.stringify(result)}\n`)
}
