import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { lstat, opendir, readFile, realpath } from 'node:fs/promises'
import { join, parse, relative, resolve } from 'node:path'
import { promisify } from 'node:util'
import { developmentDependencyClosure } from './check-release-dependencies.mjs'
import { PUBLIC_PACKAGE_FILES, PUBLIC_ROOT_MANIFEST } from './export-public-source.mjs'
import { findSecretFindings } from './validate-release-tarball.mjs'

const execFileAsync = promisify(execFile)
function cleanGitEnvironment() {
  const env = {}
  for (const [key, value] of Object.entries(process.env)) {
    if (!key.startsWith('GIT_') && value !== undefined) env[key] = value
  }
  // Ignore repository replacement objects even while checking that none exist.
  // Do not inherit user/system configuration that can redirect Git metadata.
  return {
    ...env,
    GIT_NO_REPLACE_OBJECTS: '1',
    GIT_NO_LAZY_FETCH: '1',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_ATTR_NOSYSTEM: '1',
    GIT_PAGER: 'cat',
  }
}

async function git(repository, args, options = {}) {
  const { env: _ignoredEnvironment, ...safeOptions } = options
  try {
    return await execFileAsync('git', [
      '-c', 'core.fsmonitor=false',
      '-c', 'diff.orderFile=/dev/null',
      '-c', 'log.mailmap=false',
      '-c', 'log.showSignature=false',
      '-C', repository,
      ...args,
    ], {
      ...safeOptions,
      env: cleanGitEnvironment(),
    })
  } catch {
    throw new Error('public Git command failed')
  }
}
const REQUIRED_ROOT_PATHS = new Set([
  '.github/workflows/agent-cli-public-ci.yml',
  '.github/workflows/promote-agent-cli-candidate.yml',
  '.github/workflows/release-agent-cli.yml',
  '.gitignore',
  'package-lock.json',
  'package.json',
])
const ALLOWED_PUBLIC_PATHS = new Set([
  ...REQUIRED_ROOT_PATHS,
  ...PUBLIC_PACKAGE_FILES.map((path) => `packages/agent-cli/${path}`),
])
const ALLOWED_PUBLIC_DIRECTORIES = new Set()
for (const path of ALLOWED_PUBLIC_PATHS) {
  const parts = path.split('/')
  parts.pop()
  while (parts.length > 0) {
    ALLOWED_PUBLIC_DIRECTORIES.add(parts.join('/'))
    parts.pop()
  }
}
// When a reviewed future release intentionally removes or renames a path, add
// only that old path here. Current checkout equality remains exact while the
// append-only public Git history remains verifiable without a force-push.
const HISTORICAL_PUBLIC_PATHS = new Set([])
const MAX_PUBLIC_SOURCE_BYTES = 8 * 1024 * 1024
const FORBIDDEN_NAMES = /(?:^|\/)(?:\.env(?:\.|$)|\.npmrc$|identity\.json$|wrangler(?:\.[^/]*)?\.toml$)/i
const PUBLIC_GIT_NAME = '1F4BC Release'
const PUBLIC_GIT_EMAIL = 'support@1f4bc.com'
const PUBLIC_RELEASE_MESSAGE_PREFIX = 'release: publish @1f4bcai/agent@'
const AUTHORITY_BOOTSTRAP_MESSAGE = 'chore: install agent candidate promotion authority\n'
const AUTHORITY_BOOTSTRAP_TIMESTAMP = String(Date.parse('2026-08-25T23:00:00Z') / 1000)
const LEGACY_CANONICAL_MAIN = '56d884c752a4ee44eef8de9208858e9ef8fc6423'
const PUBLIC_CI_AUTHORITY_REPAIR_MESSAGE = 'chore: repair agent candidate CI authority\n'
const PUBLIC_CI_AUTHORITY_REPAIR_TIMESTAMP = String(Date.parse('2026-08-26T17:30:00Z') / 1000)
const PUBLIC_CI_AUTHORITY_REPAIR_PARENT = '9f16eb8a351fd39a1e6f79a6d130b96c0161dd13'
const AUTHORITY_BOOTSTRAP_PATHS = Object.freeze([
  '.github/workflows/agent-cli-public-ci.yml',
  '.github/workflows/promote-agent-cli-candidate.yml',
  'packages/agent-cli/scripts/export-public-source.d.mts',
  'packages/agent-cli/scripts/export-public-source.mjs',
  'packages/agent-cli/scripts/promote-release-candidate.d.mts',
  'packages/agent-cli/scripts/promote-release-candidate.mjs',
  'packages/agent-cli/scripts/verify-public-tree.mjs',
  'packages/agent-cli/test/candidate-promotion.test.ts',
  'packages/agent-cli/test/release-pipeline.test.ts',
])
const PUBLIC_CI_AUTHORITY_REPAIR_PATHS = Object.freeze([
  '.github/workflows/agent-cli-public-ci.yml',
  'packages/agent-cli/scripts/verify-public-tree.d.mts',
  'packages/agent-cli/scripts/verify-public-tree.mjs',
  'packages/agent-cli/test/public-export.test.ts',
  'packages/agent-cli/test/release-pipeline.test.ts',
])
const REPLACEMENT_ROOT_VERSION = '0.1.3'
const STABLE_SEMVER = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/
const RETIRED_RELEASE_VERSIONS = new Set(['0.1.0', '0.1.1', '0.1.2'])
const RETIRED_RELEASE_TAGS = new Set(
  [...RETIRED_RELEASE_VERSIONS].map((version) => `agent-v${version}`),
)
const ALLOWED_PUBLIC_COMMIT_REFS = new Set([
  'refs/heads/main',
  'refs/remotes/origin/main',
  'refs/remotes/origin/HEAD',
])
const PUBLIC_VERIFICATION_MODES = new Set(['full', 'snapshot-only'])
function containsCredentialPattern(text) {
  return findSecretFindings(text).length > 0
}

function publicVerificationMode(options) {
  if (options === null || typeof options !== 'object' || Array.isArray(options)) {
    throw new Error('public verification options must be an object')
  }
  const unexpectedOptions = Object.keys(options).filter((key) => key !== 'mode')
  if (unexpectedOptions.length > 0) {
    throw new Error('public verification received an unsupported option')
  }
  const mode = options.mode ?? 'full'
  if (!PUBLIC_VERIFICATION_MODES.has(mode)) {
    throw new Error('public verification mode must be full or snapshot-only')
  }
  return mode
}

function assertPublicPackageIdentity(manifest, label) {
  if (manifest?.name !== '@1f4bcai/agent' || !STABLE_SEMVER.test(manifest?.version ?? '')) {
    throw new Error(`${label} contains an invalid package identity or version`)
  }
  if (RETIRED_RELEASE_VERSIONS.has(manifest.version)) {
    throw new Error(`${label} contains a retired package version`)
  }
  return manifest.version
}

function assertReleaseVersionAgreement(rootManifest, packageManifest, lock, label) {
  const version = assertPublicPackageIdentity(packageManifest, `${label} package manifest`)
  if (
    rootManifest?.version !== version ||
    lock?.version !== version ||
    lock?.packages?.['']?.version !== version ||
    lock?.packages?.['packages/agent-cli']?.version !== version
  ) {
    throw new Error(`${label} root, package, and lock versions must agree`)
  }
  return version
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

async function assertDedicatedGitMetadata(gitDirectory, rejectPromisorMarkers) {
  const pending = [gitDirectory]
  const linkedWorktreeMetadata = new Set([
    'commondir',
    'gitdir',
    'worktrees',
  ])
  while (pending.length > 0) {
    const directory = pending.pop()
    const handle = await opendir(directory)
    for await (const entry of handle) {
      const path = join(directory, entry.name)
      const stat = await lstat(path)
      // Git consumes these reserved paths case-insensitively on common macOS
      // filesystems, so recognize their relative spellings conservatively on
      // every platform without including the untrusted spelling in errors.
      const metadataPath = relative(gitDirectory, path).replaceAll('\\', '/').toLowerCase()
      if (linkedWorktreeMetadata.has(metadataPath)) {
        throw new Error('public repository must not contain linked-worktree Git metadata')
      }
      if (stat.isSymbolicLink()) {
        throw new Error('public Git metadata must not contain symlinks')
      }
      if (stat.isDirectory()) {
        pending.push(path)
        continue
      }
      if (!stat.isFile()) {
        throw new Error('public Git metadata must not contain special files')
      }
      if (stat.nlink !== 1) {
        throw new Error('public Git metadata must not contain multiply linked files')
      }
      if (metadataPath === 'info/attributes') {
        throw new Error('public repository must not use repository attributes')
      }
      if (metadataPath === 'config.worktree') {
        throw new Error('public repository contains unsafe local Git configuration')
      }
      if (
        rejectPromisorMarkers &&
        metadataPath.startsWith('objects/pack/') &&
        metadataPath.endsWith('.promisor')
      ) {
        throw new Error('public repository must not use partial clone or promisor storage')
      }
    }
  }
}

async function assertNoGitStorageIndirection(gitDirectory) {
  for (const [path, label] of [
    [join(gitDirectory, 'info', 'grafts'), 'legacy Git grafts'],
    [join(gitDirectory, 'objects', 'info', 'alternates'), 'alternate Git object stores'],
    [join(gitDirectory, 'objects', 'info', 'http-alternates'), 'alternate Git object stores'],
  ]) {
    try {
      const stat = await lstat(path)
      if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 0) {
        throw new Error(`public repository must not use ${label}`)
      }
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error
    }
  }
}

async function assertExactPublicWorktree(repository) {
  const pending = [{ directory: repository, prefix: '' }]
  while (pending.length > 0) {
    const { directory, prefix } = pending.pop()
    const handle = await opendir(directory)
    for await (const entry of handle) {
      if (prefix === '' && entry.name === '.git') continue
      const path = prefix === '' ? entry.name : `${prefix}/${entry.name}`
      const absolutePath = join(directory, entry.name)
      const stat = await lstat(absolutePath)
      if (stat.isSymbolicLink()) {
        throw new Error('public worktree contains a symlink at a disallowed path; unallowlisted worktree path present')
      }
      if (stat.isDirectory()) {
        if (!ALLOWED_PUBLIC_DIRECTORIES.has(path)) {
          throw new Error('public worktree contains a disallowed path; unallowlisted worktree path present')
        }
        pending.push({ directory: absolutePath, prefix: path })
        continue
      }
      if (!stat.isFile()) {
        throw new Error('public worktree contains a special file at a disallowed path; unallowlisted worktree path present')
      }
      if (stat.nlink !== 1) {
        throw new Error('public worktree must not contain multiply linked files')
      }
      if (!allowedPublicPath(path)) {
        throw new Error('public worktree contains a disallowed path; unallowlisted worktree path present')
      }
    }
  }
}

async function localGitConfigurationKeys(repository, gitDirectory) {
  try {
    const configStat = await lstat(join(gitDirectory, 'config'))
    if (!configStat.isFile() || configStat.size > 1024 * 1024) {
      throw new Error('invalid local Git configuration')
    }
    const { stdout } = await execFileAsync(
      'git', [
        '-c', 'core.fsmonitor=false',
        '-c', 'diff.orderFile=/dev/null',
        '-c', 'log.mailmap=false',
        '-c', 'log.showSignature=false',
        'config', '--file', join(gitDirectory, 'config'), '--no-includes',
        '--list', '-z',
      ],
      {
        // Never let repository discovery consult an unvalidated commondir or
        // worktree config while parsing this one explicit, size-bounded file.
        cwd: parse(repository).root,
        encoding: 'utf8',
        maxBuffer: 1024 * 1024,
        env: cleanGitEnvironment(),
      },
    )
    return stdout.split('\0').filter(Boolean).map((record) => {
      const boundary = record.indexOf('\n')
      if (boundary < 1) throw new Error('invalid local Git configuration entry')
      return {
        key: record.slice(0, boundary).toLowerCase(),
        value: record.slice(boundary + 1),
      }
    })
  } catch {
    throw new Error('public repository local Git configuration is invalid')
  }
}

function assertCanonicalLocalGitConfiguration(entries) {
  const allowed = entries.every(({ key, value }) => {
    if (key === 'core.repositoryformatversion') return value === '0'
    if (key === 'core.filemode') return value === 'true' || value === 'false'
    if (key === 'core.bare') return value === 'false'
    if (key === 'core.logallrefupdates') return value === 'true'
    if (key === 'core.ignorecase') return value === 'true' || value === 'false'
    if (key === 'core.precomposeunicode') return value === 'true' || value === 'false'
    if (key === 'gc.auto') return value === '0'
    if (key === 'maintenance.auto') return value === 'false'
    if (key === 'user.name') return value === PUBLIC_GIT_NAME
    if (key === 'user.email') return value === PUBLIC_GIT_EMAIL
    if (key === 'remote.origin.url') {
      return value === 'https://github.com/1f4bcai/1f4bc-agent' ||
        value === 'https://github.com/1f4bcai/1f4bc-agent.git'
    }
    if (key === 'remote.origin.fetch') {
      return value === '+refs/heads/*:refs/remotes/origin/*'
    }
    if (key === 'branch.main.remote') return value === 'origin'
    if (key === 'branch.main.merge') return value === 'refs/heads/main'
    return false
  })
  if (!allowed) throw new Error('public repository contains unsafe local Git configuration')
}

function assertNoPartialCloneConfiguration(entries) {
  const partialCloneConfiguration = entries.some(({ key: normalized }) => {
    return normalized === 'extensions.partialclone' ||
      /^remote\..+\.(?:promisor|partialclonefilter)$/.test(normalized)
  })
  if (partialCloneConfiguration) {
    throw new Error('public repository must not use partial clone or promisor configuration')
  }
}

async function assertCompleteObjectDatabase(repository) {
  let result
  try {
    result = await git(
      repository,
      ['fsck', '--full', '--strict', '--no-reflogs', '--unreachable', '--no-progress'],
      { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 },
    )
  } catch {
    throw new Error('public repository failed strict Git object verification')
  }
  if (result.stdout.trim() !== '' || result.stderr.trim() !== '') {
    throw new Error('public repository contains unreachable Git objects or strict fsck diagnostics')
  }
}

function decodePublicText(contents, label) {
  const bytes = Buffer.isBuffer(contents) ? contents : Buffer.from(contents)
  if (bytes.byteLength > MAX_PUBLIC_SOURCE_BYTES) {
    throw new Error(`${label} exceeds the public source size limit`)
  }
  if (bytes.includes(0)) throw new Error(`${label} contains binary NUL bytes`)
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch {
    throw new Error(`${label} is not valid UTF-8 text`)
  }
}

async function readGitObjectText(repository, type, hash) {
  const { stdout: sizeOutput } = await git(repository, ['cat-file', '-s', hash], {
    encoding: 'utf8',
  })
  const size = Number(sizeOutput.trim())
  if (!Number.isSafeInteger(size) || size < 0) throw new Error(`invalid Git object size for ${hash}`)
  if (size > MAX_PUBLIC_SOURCE_BYTES) {
    throw new Error(`public history ${type} object exceeds the public source size limit`)
  }
  const { stdout } = await git(
    repository, ['cat-file', type, hash],
    // Keep the object byte-exact. Asking execFile for text would replace
    // malformed UTF-8 before the fatal decoder below ever sees it.
    { encoding: null, maxBuffer: MAX_PUBLIC_SOURCE_BYTES + 1 },
  )
  return decodePublicText(stdout, `public history ${type} object`)
}

async function publicPackageVersionAt(repository, commit, cache) {
  const cached = cache.get(commit)
  if (cached !== undefined) return cached
  let rootManifest
  let packageManifest
  let lock
  try {
    const [rootResult, packageResult, lockResult] = await Promise.all([
      git(repository, ['cat-file', 'blob', `${commit}:package.json`], {
        encoding: null,
        maxBuffer: MAX_PUBLIC_SOURCE_BYTES + 1,
      }),
      git(repository, ['cat-file', 'blob', `${commit}:packages/agent-cli/package.json`], {
        encoding: null,
        maxBuffer: MAX_PUBLIC_SOURCE_BYTES + 1,
      }),
      git(repository, ['cat-file', 'blob', `${commit}:package-lock.json`], {
        encoding: null,
        maxBuffer: MAX_PUBLIC_SOURCE_BYTES + 1,
      }),
    ])
    rootManifest = JSON.parse(
      decodePublicText(rootResult.stdout, 'public historical root manifest'),
    )
    packageManifest = JSON.parse(
      decodePublicText(packageResult.stdout, 'public historical package manifest'),
    )
    lock = JSON.parse(decodePublicText(lockResult.stdout, 'public historical lock'))
  } catch {
    throw new Error('public history contains invalid release manifests')
  }
  const version = assertReleaseVersionAgreement(
    rootManifest,
    packageManifest,
    lock,
    'public history',
  )
  cache.set(commit, version)
  return version
}

async function assertAuthorityBootstrapDiff(repository, commit) {
  const { stdout } = await git(repository, [
    'diff-tree', '--no-commit-id', '--name-only', '--no-renames', '-r', '-z', commit,
  ], { encoding: 'utf8', maxBuffer: 1024 * 1024 })
  const changed = stdout.split('\0').filter(Boolean).sort()
  if (JSON.stringify(changed) !== JSON.stringify([...AUTHORITY_BOOTSTRAP_PATHS].sort())) {
    throw new Error('public authority-bootstrap commit differs from the exact approved path set')
  }
}

async function assertPublicCiAuthorityRepairDiff(repository, commit) {
  const { stdout } = await git(repository, [
    'diff-tree', '--no-commit-id', '--name-only', '--no-renames', '-r', '-z', commit,
  ], { encoding: 'utf8', maxBuffer: 1024 * 1024 })
  const changed = stdout.split('\0').filter(Boolean).sort()
  if (JSON.stringify(changed) !== JSON.stringify([...PUBLIC_CI_AUTHORITY_REPAIR_PATHS].sort())) {
    throw new Error('public CI authority-repair commit differs from the exact approved path set')
  }
}

export function assertPublicCiAuthorityRepairPlacement({
  commit,
  parent,
  version,
  authorTimestamp,
}) {
  if (
    commit === PUBLIC_CI_AUTHORITY_REPAIR_PARENT ||
    parent !== PUBLIC_CI_AUTHORITY_REPAIR_PARENT ||
    version !== REPLACEMENT_ROOT_VERSION ||
    authorTimestamp !== PUBLIC_CI_AUTHORITY_REPAIR_TIMESTAMP
  ) {
    throw new Error('public CI authority-repair commit is not the exact pinned history extension')
  }
}

async function assertPublicCommitMetadata(repository, commit, text, versionCache) {
  const boundary = text.indexOf('\n\n')
  if (boundary < 0) throw new Error('public commit metadata is malformed')
  const headers = text.slice(0, boundary).split('\n')
  const body = text.slice(boundary + 2)
  const tree = headers.filter((line) => line.startsWith('tree '))
  const parents = headers.filter((line) => line.startsWith('parent '))
  const authors = headers.filter((line) => line.startsWith('author '))
  const committers = headers.filter((line) => line.startsWith('committer '))
  const orderedHeaders = parents.length === 1
    ? [tree[0], parents[0], authors[0], committers[0]]
    : [tree[0], authors[0], committers[0]]
  if (
    tree.length !== 1 ||
    parents.length > 1 ||
    authors.length !== 1 ||
    committers.length !== 1 ||
    headers.length !== tree.length + parents.length + authors.length + committers.length ||
    !/^tree [0-9a-f]{40,64}$/.test(tree[0]) ||
    parents.some((line) => !/^parent [0-9a-f]{40,64}$/.test(line)) ||
    headers.some((line, index) => line !== orderedHeaders[index])
  ) {
    throw new Error('public commit contains unsupported metadata headers')
  }
  const identity = `${PUBLIC_GIT_NAME} <${PUBLIC_GIT_EMAIL}>`
  const author = new RegExp(`^author ${identity.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')} (0|[1-9][0-9]*) \\+0000$`).exec(authors[0])
  const committer = new RegExp(`^committer ${identity.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')} (0|[1-9][0-9]*) \\+0000$`).exec(committers[0])
  if (!author || !committer || author[1] !== committer[1]) {
    throw new Error('public commit does not use the organization-controlled Git identity')
  }
  const version = await publicPackageVersionAt(repository, commit, versionCache)
  if (body === `${PUBLIC_RELEASE_MESSAGE_PREFIX}${version}\n`) {
    return { authorityBootstrap: false, authorityRepair: false, version }
  }
  if (body === PUBLIC_CI_AUTHORITY_REPAIR_MESSAGE) {
    if (parents.length !== 1) {
      throw new Error('public CI authority-repair commit is not the exact pinned history extension')
    }
    assertPublicCiAuthorityRepairPlacement({
      commit,
      parent: parents[0].slice('parent '.length),
      version,
      authorTimestamp: author[1],
    })
    const parentVersion = await publicPackageVersionAt(
      repository, PUBLIC_CI_AUTHORITY_REPAIR_PARENT, versionCache,
    )
    if (parentVersion !== REPLACEMENT_ROOT_VERSION) {
      throw new Error('public CI authority repair is not based on the pinned authority main')
    }
    await assertPublicCiAuthorityRepairDiff(repository, commit)
    return { authorityBootstrap: false, authorityRepair: true, version }
  }
  if (
    body !== AUTHORITY_BOOTSTRAP_MESSAGE ||
    commit === LEGACY_CANONICAL_MAIN ||
    parents.length !== 1 ||
    parents[0] !== `parent ${LEGACY_CANONICAL_MAIN}` ||
    version !== REPLACEMENT_ROOT_VERSION ||
    author[1] !== AUTHORITY_BOOTSTRAP_TIMESTAMP
  ) {
    throw new Error('public release commit message does not match its package tree')
  }
  const parentVersion = await publicPackageVersionAt(
    repository, LEGACY_CANONICAL_MAIN, versionCache,
  )
  if (parentVersion !== REPLACEMENT_ROOT_VERSION) {
    throw new Error('public authority bootstrap is not based on the replacement root')
  }
  await assertAuthorityBootstrapDiff(repository, commit)
  return { authorityBootstrap: true, authorityRepair: false, version }
}

async function assertPublicRefs(repository, versionCache) {
  const { stdout } = await git(
    repository,
    ['for-each-ref', '--format=%(refname)%00%(objecttype)%00%(objectname)%00%(symref)'],
    { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 },
  )
  let localMain
  let remoteMain
  const releaseTags = []
  for (const record of stdout.split('\n').filter(Boolean)) {
    const fields = record.split('\0')
    if (fields.length !== 4) throw new Error('public repository contains malformed Git refs')
    const [ref, type, commit, symref] = fields
    if (!ref.startsWith('refs/tags/')) {
      if (
        !ALLOWED_PUBLIC_COMMIT_REFS.has(ref) ||
        type !== 'commit' ||
        (ref === 'refs/remotes/origin/HEAD'
          ? symref !== 'refs/remotes/origin/main'
          : symref !== '')
      ) {
        throw new Error('public repository contains an unexpected public Git ref')
      }
      if (ref === 'refs/heads/main') localMain = commit
      if (ref === 'refs/remotes/origin/main') remoteMain = commit
      continue
    }
    const tag = ref.slice('refs/tags/'.length)
    if (RETIRED_RELEASE_TAGS.has(tag)) throw new Error('public repository contains a retired release tag')
    if (type !== 'commit' || symref !== '') {
      throw new Error('public repository allows only lightweight release tags')
    }
    const version = await publicPackageVersionAt(repository, commit, versionCache)
    if (ref !== `refs/tags/agent-v${version}`) {
      throw new Error('public release tag does not match its package tree')
    }
    releaseTags.push(commit)
  }
  const canonicalMain = localMain ?? remoteMain
  if (canonicalMain === undefined) {
    throw new Error('public repository is missing a canonical main ref')
  }
  if (localMain !== undefined && remoteMain !== undefined && localMain !== remoteMain) {
    throw new Error('public repository canonical main refs differ')
  }
  for (const commit of releaseTags) {
    try {
      await git(repository, ['merge-base', '--is-ancestor', commit, canonicalMain])
    } catch {
      throw new Error('public release tag is not reachable from canonical main')
    }
  }
  let head
  try {
    const { stdout: headOutput } = await git(
      repository, ['rev-parse', '--verify', 'HEAD^{commit}'], { encoding: 'utf8' },
    )
    head = headOutput.trim()
  } catch {
    throw new Error('public HEAD cannot be resolved to an allowed commit')
  }
  if (head !== canonicalMain && !releaseTags.includes(head)) {
    throw new Error('public HEAD must equal canonical main or an allowed release tag target')
  }
}

export function allowedPublicPath(path) {
  return ALLOWED_PUBLIC_PATHS.has(path)
}

function allowedHistoricalPath(path) {
  return ALLOWED_PUBLIC_PATHS.has(path) || HISTORICAL_PUBLIC_PATHS.has(path)
}

function parseIndex(output) {
  return output.split('\0').filter(Boolean).map((entry) => {
    const match = /^(\d{6}) ([0-9a-f]{40,64}) (\d+)\t(.+)$/.exec(entry)
    if (!match) throw new Error('public index contains a malformed entry')
    if (match[3] !== '0') throw new Error('public index contains an unresolved stage')
    return { mode: match[1], blob: match[2], path: match[4] }
  })
}

function parseHeadTree(output) {
  return output.split('\0').filter(Boolean).map((entry) => {
    const match = /^(\d{6}) ([^ ]+) ([0-9a-f]{40,64})\t([\s\S]+)$/.exec(entry)
    if (!match) throw new Error('public HEAD contains a malformed tree entry')
    return { mode: match[1], type: match[2], blob: match[3], path: match[4] }
  })
}

export async function verifyPublicTree(root = process.cwd(), options = {}) {
  const verificationMode = publicVerificationMode(options)
  const repository = await realpath(resolve(root))
  const gitMetadataPath = join(repository, '.git')
  const gitMetadataStat = await lstat(gitMetadataPath)
  if (gitMetadataStat.isSymbolicLink() || !gitMetadataStat.isDirectory()) {
    throw new Error('public verification requires .git to be a real local directory')
  }
  const gitObjectsPath = join(gitMetadataPath, 'objects')
  const gitObjectsStat = await lstat(gitObjectsPath)
  if (gitObjectsStat.isSymbolicLink() || !gitObjectsStat.isDirectory()) {
    throw new Error('public verification requires .git/objects to be a real local directory')
  }
  await assertDedicatedGitMetadata(gitMetadataPath, true)
  await assertNoGitStorageIndirection(gitMetadataPath)
  await assertExactPublicWorktree(repository)
  const localConfigurationKeys = await localGitConfigurationKeys(repository, gitMetadataPath)
  assertNoPartialCloneConfiguration(localConfigurationKeys)
  assertCanonicalLocalGitConfiguration(localConfigurationKeys)
  const { stdout: topLevelOutput } = await git(repository, ['rev-parse', '--show-toplevel'], {
    encoding: 'utf8',
  })
  if (await realpath(topLevelOutput.trim()) !== repository) {
    throw new Error('Git metadata is not canonically bound to the intended public repository')
  }
  const { stdout: gitDirectoryOutput } = await git(
    repository, ['rev-parse', '--path-format=absolute', '--absolute-git-dir'],
    { encoding: 'utf8' },
  )
  const gitDirectory = await realpath(gitDirectoryOutput.trim())
  const expectedGitDirectory = await realpath(gitMetadataPath)
  const { stdout: commonDirectoryOutput } = await git(
    repository, ['rev-parse', '--path-format=absolute', '--git-common-dir'],
    { encoding: 'utf8' },
  )
  const commonDirectory = await realpath(commonDirectoryOutput.trim())
  if (gitDirectory !== expectedGitDirectory || commonDirectory !== gitDirectory) {
    throw new Error('public verification requires one dedicated non-linked Git repository')
  }
  const { stdout: objectFormatOutput } = await git(
    repository, ['rev-parse', '--show-object-format'], { encoding: 'utf8' },
  )
  if (objectFormatOutput.trim() !== 'sha1') {
    throw new Error('public repository requires the SHA-1 Git object format')
  }
  if (verificationMode === 'full') {
    const { stdout: shallowOutput } = await git(
      repository, ['rev-parse', '--is-shallow-repository'], { encoding: 'utf8' },
    )
    if (shallowOutput.trim() !== 'false') {
      throw new Error('public repository history must be complete, not shallow')
    }
    const { stdout: replacementRefs } = await git(
      repository, ['for-each-ref', '--format=%(refname)%00', 'refs/replace'],
      { encoding: 'utf8', maxBuffer: 1024 * 1024 },
    )
    if (replacementRefs.length > 0) throw new Error('public repository must not contain replace refs')
    await assertCompleteObjectDatabase(repository)
  }

  const { stdout: indexOutput } = await git(
    repository, ['ls-files', '--stage', '-z'], { encoding: 'utf8' },
  )
  const entries = parseIndex(indexOutput)
  const { stdout: indexFlagsOutput } = await git(
    repository, ['ls-files', '-v', '-z'], { encoding: 'utf8' },
  )
  const indexFlags = new Map()
  for (const entry of indexFlagsOutput.split('\0').filter(Boolean)) {
    if (entry.length < 3 || entry[1] !== ' ' || entry[0] !== 'H') {
      throw new Error('public index contains a non-normal index flag')
    }
    indexFlags.set(entry.slice(2), entry[0])
  }
  if (
    indexFlags.size !== entries.length ||
    entries.some(({ path }) => !indexFlags.has(path))
  ) {
    throw new Error('public index flags do not match its staged entries')
  }
  const { stdout: headTreeOutput } = await git(
    repository, ['ls-tree', '-rz', '--full-tree', 'HEAD'],
    { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 },
  )
  const headEntries = parseHeadTree(headTreeOutput)
  const headByPath = new Map(headEntries.map((entry) => [entry.path, entry]))
  if (
    headByPath.size !== entries.length ||
    entries.some(({ mode, blob, path }) => {
      const head = headByPath.get(path)
      return head === undefined || head.type !== 'blob' || head.mode !== mode || head.blob !== blob
    })
  ) {
    throw new Error('public index must exactly match HEAD')
  }
  const tracked = new Set(entries.map(({ path }) => path))
  for (const required of ALLOWED_PUBLIC_PATHS) {
    if (!tracked.has(required)) throw new Error(`public tree is missing ${required}`)
  }
  for (const { mode, blob, path } of entries) {
    if (!allowedPublicPath(path)) throw new Error('public tree contains disallowed path')
    if (mode !== '100644' && mode !== '100755') {
      throw new Error(`public tree contains a symlink, submodule, or special mode at ${path}`)
    }
    if (FORBIDDEN_NAMES.test(path)) throw new Error(`public tree contains sensitive path ${path}`)
    const stat = await lstat(resolve(repository, path))
    if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`public path is not a regular file: ${path}`)
    if (stat.nlink !== 1) throw new Error('public worktree must not contain multiply linked files')
    if (stat.size > MAX_PUBLIC_SOURCE_BYTES) {
      throw new Error(`public path ${path} exceeds the public source size limit`)
    }
    const executable = (stat.mode & 0o111) !== 0
    if (executable !== (mode === '100755')) {
      throw new Error('public worktree executable state differs from its index mode')
    }
    const contents = await readFile(resolve(repository, path))
    const computedBlob = createHash('sha1')
      .update(Buffer.from(`blob ${contents.byteLength}\0`))
      .update(contents)
      .digest('hex')
    if (computedBlob !== blob) {
      throw new Error('public worktree blob object ID does not match its index')
    }
    let indexedContents
    try {
      const result = await git(repository, ['cat-file', 'blob', blob], {
        encoding: null,
        maxBuffer: MAX_PUBLIC_SOURCE_BYTES + 1,
      })
      indexedContents = result.stdout
    } catch {
      throw new Error('public worktree file bytes do not match its index blob')
    }
    if (!contents.equals(indexedContents)) {
      throw new Error('public worktree file bytes do not match its index blob')
    }
    const text = decodePublicText(contents, `public path ${path}`)
    if (containsCredentialPattern(text)) {
      throw new Error(`public tree contains a credential pattern in ${path}`)
    }
  }
  if (verificationMode === 'snapshot-only') await assertCompleteObjectDatabase(repository)

  if (verificationMode === 'full') {
    const { stdout: historicalNames } = await git(
      repository, ['log', '--all', '--format=', '--name-only', '--no-renames', '-z'],
      { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 },
    )
    for (const rawPath of historicalNames.split('\0')) {
      const path = rawPath.trim()
      if (path && !allowedHistoricalPath(path)) {
        throw new Error('public history contains disallowed path')
      }
    }

    const { stdout: commitListing } = await git(
      repository, ['rev-list', '--all'], { encoding: 'utf8' },
    )
    const versionCache = new Map()
    const authorityBootstrapCommits = new Set()
    const authorityRepairCommits = new Set()
    const commits = commitListing.split('\n').filter(Boolean)
    for (const commit of commits) {
      const { stdout: treeListing } = await git(
        repository, ['ls-tree', '-rz', '--full-tree', commit],
        { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 },
      )
      for (const entry of treeListing.split('\0').filter(Boolean)) {
        const match = /^(\d{6}) [^ ]+ [0-9a-f]+\t([\s\S]+)$/.exec(entry)
        if (!match) throw new Error(`unexpected historical tree entry in ${commit}`)
        const [, mode, path] = match
        if (!allowedHistoricalPath(path)) {
          throw new Error('public history contains disallowed path')
        }
        if (mode !== '100644' && mode !== '100755') {
          throw new Error(`public history contains a special file mode at ${path}`)
        }
      }
    }

    const { stdout: objectListing } = await git(
      repository, ['rev-list', '--objects', '--all'], { encoding: 'utf8' },
    )
    const checkedBlobs = new Set()
    const checkedMetadataObjects = new Set()
    for (const line of objectListing.split('\n').filter(Boolean)) {
      const [hash, ...pathParts] = line.split(' ')
      if (!hash) continue
      const { stdout: objectType } = await git(
        repository, ['cat-file', '-t', hash], { encoding: 'utf8' },
      )
      const type = objectType.trim()
      if (type === 'commit' || type === 'tag') {
        if (checkedMetadataObjects.has(hash)) continue
        checkedMetadataObjects.add(hash)
        // Scan the raw object payload, not only fields rendered by `git log`.
        // Signed commits/tags and optional headers (for example gpgsig or
        // encoding) can contain material that formatted log placeholders omit.
        const text = await readGitObjectText(repository, type, hash)
        if (containsCredentialPattern(text)) {
          throw new Error(`public history contains a credential pattern in a ${type} object`)
        }
        if (type === 'tag') {
          throw new Error('public repository allows only lightweight release tags')
        }
        const metadata = await assertPublicCommitMetadata(repository, hash, text, versionCache)
        if (metadata.authorityBootstrap) authorityBootstrapCommits.add(hash)
        if (metadata.authorityRepair) authorityRepairCommits.add(hash)
        continue
      }
      if (type !== 'blob') continue
      const historicalPath = pathParts.join(' ')
      if (!historicalPath || !allowedHistoricalPath(historicalPath)) {
        throw new Error('public history contains disallowed path')
      }
      if (checkedBlobs.has(hash)) continue
      checkedBlobs.add(hash)
      const historicalContents = await readGitObjectText(repository, 'blob', hash)
      if (containsCredentialPattern(historicalContents)) {
        throw new Error(`public history contains a credential pattern in ${historicalPath}`)
      }
    }

    const { stdout: commitMessages } = await git(
      repository, [
        'log', '--all',
        '--format=%H%x00%an%x00%ae%x00%cn%x00%ce%x00%B%x00',
      ],
      { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 },
    )
    if (containsCredentialPattern(commitMessages)) {
      throw new Error('public history contains a credential pattern in a commit message')
    }
    const { stdout: tagMessages } = await git(
      repository, [
        'for-each-ref',
        '--format=%(refname)%00%(taggername)%00%(taggeremail)%00%(contents)%00',
        'refs/tags',
      ],
      { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 },
    )
    if (containsCredentialPattern(tagMessages)) {
      throw new Error('public history contains a credential pattern in a tag message')
    }
    const { stdout: refNames } = await git(
      repository, ['for-each-ref', '--format=%(refname)%00'],
      { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 },
    )
    if (containsCredentialPattern(refNames)) {
      throw new Error('public repository contains a credential pattern in a ref name')
    }
    await assertPublicRefs(repository, versionCache)
    const { stdout: rootListing } = await git(
      repository, ['rev-list', '--max-parents=0', '--all'], { encoding: 'utf8' },
    )
    const roots = rootListing.split('\n').filter(Boolean)
    if (roots.length !== 1) {
      throw new Error('public replacement history must contain exactly one root commit')
    }
    const rootVersion = await publicPackageVersionAt(repository, roots[0], versionCache)
    if (rootVersion !== REPLACEMENT_ROOT_VERSION) {
      throw new Error(
        `public replacement history root must be version ${REPLACEMENT_ROOT_VERSION}`,
      )
    }
    const { stdout: chronologicalListing } = await git(
      repository,
      ['rev-list', '--reverse', '--topo-order', '--all'],
      { encoding: 'utf8' },
    )
    let previousVersion
    let previousCommit
    let authorityBootstrapSeen = false
    let authorityRepairSeen = false
    const chronologicalCommits = chronologicalListing.split('\n').filter(Boolean)
    for (const commit of chronologicalCommits) {
      const version = await publicPackageVersionAt(repository, commit, versionCache)
      const authorityBootstrap = authorityBootstrapCommits.has(commit)
      const authorityRepair = authorityRepairCommits.has(commit)
      if (authorityBootstrap) {
        if (
          authorityBootstrapSeen ||
          previousCommit !== LEGACY_CANONICAL_MAIN ||
          previousVersion !== REPLACEMENT_ROOT_VERSION ||
          version !== REPLACEMENT_ROOT_VERSION
        ) {
          throw new Error('public history authority bootstrap is not the one-time root child')
        }
        authorityBootstrapSeen = true
      } else if (authorityRepair) {
        if (
          authorityRepairSeen ||
          !authorityBootstrapSeen ||
          previousCommit !== PUBLIC_CI_AUTHORITY_REPAIR_PARENT ||
          previousVersion !== REPLACEMENT_ROOT_VERSION ||
          version !== REPLACEMENT_ROOT_VERSION
        ) {
          throw new Error('public history CI authority repair is not the one-time pinned extension')
        }
        authorityRepairSeen = true
      } else if (
        previousVersion !== undefined && compareStableVersions(previousVersion, version) >= 0
      ) {
        throw new Error('public history package versions must increase strictly')
      }
      previousVersion = version
      previousCommit = commit
    }
    if (
      roots[0] === LEGACY_CANONICAL_MAIN &&
      chronologicalCommits.length > 1 &&
      !authorityBootstrapSeen
    ) {
      throw new Error('public replacement history is missing the pinned authority bootstrap')
    }
    if (
      chronologicalCommits.includes(PUBLIC_CI_AUTHORITY_REPAIR_PARENT) &&
      chronologicalCommits.at(-1) !== PUBLIC_CI_AUTHORITY_REPAIR_PARENT &&
      !authorityRepairSeen
    ) {
      throw new Error('public replacement history is missing the pinned CI authority repair')
    }
  }

  const rootManifest = JSON.parse(await readFile(resolve(repository, 'package.json'), 'utf8'))
  const packageManifest = JSON.parse(
    await readFile(resolve(repository, 'packages/agent-cli/package.json'), 'utf8'),
  )
  const lock = JSON.parse(await readFile(resolve(repository, 'package-lock.json'), 'utf8'))
  const currentVersion = assertReleaseVersionAgreement(
    rootManifest,
    packageManifest,
    lock,
    'public current release',
  )
  if (JSON.stringify(rootManifest) !== JSON.stringify({
    ...PUBLIC_ROOT_MANIFEST,
    version: currentVersion,
  })) {
    throw new Error('public root manifest differs from the minimal allowlist')
  }
  const allowedLockPaths = new Set([
    '',
    'packages/agent-cli',
    'node_modules/@1f4bcai/agent',
    ...developmentDependencyClosure(lock, packageManifest).map(({ lockPath }) => lockPath),
  ])
  const actualLockPaths = Object.keys(lock.packages ?? {})
  for (const lockPath of actualLockPaths) {
    if (!allowedLockPaths.has(lockPath)) throw new Error('public lock contains unrelated package data')
  }
  if (actualLockPaths.length !== allowedLockPaths.size) {
    throw new Error('public lock omits an executable dependency closure entry')
  }

  for (const workflow of [
    '.github/workflows/agent-cli-public-ci.yml',
    '.github/workflows/promote-agent-cli-candidate.yml',
    '.github/workflows/release-agent-cli.yml',
  ]) {
    const text = await readFile(resolve(repository, workflow), 'utf8')
    if (/(?:^|[;&|]\s*|\brun:\s*)npm\s+publish\b/m.test(text)) {
      throw new Error(`public workflow contains direct npm publish in ${workflow}`)
    }
  }
  return { trackedFiles: entries.length, lockedPackages: actualLockPaths.length }
}

if (process.argv[1] && resolve(process.argv[1]) === new URL(import.meta.url).pathname) {
  const args = process.argv.slice(2)
  const mode = args.length === 0
    ? 'full'
    : args.length === 1 && args[0] === '--snapshot-only'
      ? 'snapshot-only'
      : null
  if (mode === null) {
    throw new Error('usage: verify-public-tree.mjs [--snapshot-only]')
  }
  process.stdout.write(`${JSON.stringify(await verifyPublicTree(process.cwd(), { mode }), null, 2)}\n`)
}
