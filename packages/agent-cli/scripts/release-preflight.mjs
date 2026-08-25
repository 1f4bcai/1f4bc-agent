import { execFile } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)
const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const repositoryRoot = resolve(packageRoot, '..', '..')
const TRUSTED_PACKAGE = '@1f4bcai/agent'
const TRUSTED_REPOSITORY = '1f4bcai/1f4bc-agent'
const TRUSTED_REPOSITORY_URL = `git+https://github.com/${TRUSTED_REPOSITORY}.git`
const RETIRED_RELEASE_VERSIONS = new Set(['0.1.0', '0.1.1', '0.1.2'])
const MAX_RESPONSE_BYTES = 64 * 1024

function assertReleaseManifest(manifest) {
  if (
    manifest?.name !== TRUSTED_PACKAGE ||
    !/^\d+\.\d+\.\d+$/.test(manifest?.version ?? '') ||
    manifest?.repository?.url !== TRUSTED_REPOSITORY_URL
  ) {
    throw new Error('release preflight requires the trusted package name, version, and repository')
  }
  if (RETIRED_RELEASE_VERSIONS.has(manifest.version)) {
    throw new Error('release preflight refuses a retired release version')
  }
  return {
    packageName: manifest.name,
    version: manifest.version,
    tag: `agent-v${manifest.version}`,
  }
}

async function responseJson(response, label) {
  const bytes = new Uint8Array(await response.arrayBuffer())
  if (bytes.byteLength > MAX_RESPONSE_BYTES) {
    throw new Error(`${label} response exceeds the preflight size limit`)
  }
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
  } catch {
    throw new Error(`${label} returned invalid JSON`)
  }
}

async function defaultGit(args, cwd) {
  try {
    const { stdout } = await execFileAsync('git', ['-C', cwd, ...args], {
      encoding: 'utf8',
      env: {
        PATH: process.env.PATH,
        GIT_CONFIG_NOSYSTEM: '1',
        GIT_CONFIG_GLOBAL: '/dev/null',
        GIT_NO_REPLACE_OBJECTS: '1',
      },
    })
    return { status: 0, stdout }
  } catch (error) {
    if (typeof error?.code === 'number') {
      return { status: error.code, stdout: String(error.stdout ?? '') }
    }
    throw error
  }
}

async function fetchExact(fetcher, url, label) {
  let response
  try {
    response = await fetcher(url, {
      headers: {
        Accept: 'application/json',
        'User-Agent': '1f4bc-release-preflight',
      },
      redirect: 'error',
      signal: AbortSignal.timeout(10_000),
    })
  } catch (error) {
    throw new Error(`${label} availability check failed`, { cause: error })
  }
  return response
}

async function assertNpmVersionAvailable(fetcher, packageName, version) {
  const url = `https://registry.npmjs.org/${encodeURIComponent(packageName)}/${encodeURIComponent(version)}`
  const response = await fetchExact(fetcher, url, 'npm registry')
  await response.body?.cancel()
  if (response.status === 200) {
    throw new Error(`${packageName}@${version} is already published and cannot be replaced`)
  }
  if (response.status !== 404) {
    throw new Error(`npm registry availability check failed closed with HTTP ${response.status}`)
  }
}

async function githubTagObject(fetcher, tag) {
  const url = `https://api.github.com/repos/${TRUSTED_REPOSITORY}/git/ref/tags/${encodeURIComponent(tag)}`
  const response = await fetchExact(fetcher, url, 'GitHub tag')
  if (response.status === 404) {
    await response.body?.cancel()
    return null
  }
  if (response.status !== 200) {
    await response.body?.cancel()
    throw new Error(`GitHub tag availability check failed closed with HTTP ${response.status}`)
  }
  const value = await responseJson(response, 'GitHub tag')
  if (
    value?.ref !== `refs/tags/${tag}` ||
    !['commit', 'tag'].includes(value?.object?.type) ||
    !/^[0-9a-f]{40}$/.test(value?.object?.sha ?? '')
  ) {
    throw new Error('GitHub returned malformed exact-tag metadata')
  }
  return value.object
}

async function resolveGithubTagCommit(fetcher, object) {
  let current = object
  const seen = new Set()
  for (let depth = 0; depth < 5; depth += 1) {
    if (current.type === 'commit') return current.sha
    if (current.type !== 'tag' || seen.has(current.sha)) break
    seen.add(current.sha)
    const url = `https://api.github.com/repos/${TRUSTED_REPOSITORY}/git/tags/${current.sha}`
    const response = await fetchExact(fetcher, url, 'GitHub annotated tag')
    if (response.status !== 200) {
      await response.body?.cancel()
      throw new Error(`GitHub annotated-tag check failed closed with HTTP ${response.status}`)
    }
    const value = await responseJson(response, 'GitHub annotated tag')
    if (
      value?.sha !== current.sha ||
      !['commit', 'tag'].includes(value?.object?.type) ||
      !/^[0-9a-f]{40}$/.test(value?.object?.sha ?? '')
    ) {
      throw new Error('GitHub returned malformed annotated-tag metadata')
    }
    current = value.object
  }
  throw new Error('GitHub tag does not resolve uniquely to a commit')
}

async function exactLocalCommit(git, cwd, revision, label) {
  const result = await git(['rev-parse', '--verify', `${revision}^{commit}`], cwd)
  const value = result.stdout.trim()
  if (result.status !== 0 || !/^[0-9a-f]{40}$/.test(value)) {
    throw new Error(`${label} does not resolve to one local commit`)
  }
  return value
}

/**
 * `prepare` runs before a tag is created and rejects either a local or remote
 * immutable tag. `tagged-ci` runs from that tag and proves tag -> HEAD -> the
 * workflow commit exactly. Both modes reject an npm version that already exists.
 */
export async function releasePreflight(options = {}) {
  const {
    mode,
    tag,
    commit,
    manifest = JSON.parse(await readFile(resolve(packageRoot, 'package.json'), 'utf8')),
    fetcher = fetch,
    git = defaultGit,
    cwd = repositoryRoot,
  } = options
  if (mode !== 'prepare' && mode !== 'tagged-ci') {
    throw new Error('release preflight mode must be prepare or tagged-ci')
  }
  const coordinates = assertReleaseManifest(manifest)
  await assertNpmVersionAvailable(fetcher, coordinates.packageName, coordinates.version)

  const remoteTag = await githubTagObject(fetcher, coordinates.tag)
  if (mode === 'prepare') {
    const local = await git(['show-ref', '--verify', '--quiet', `refs/tags/${coordinates.tag}`], cwd)
    if (local.status === 0) {
      throw new Error(`immutable release tag ${coordinates.tag} already exists locally`)
    }
    if (local.status !== 1) {
      throw new Error('local release-tag availability check failed closed')
    }
    if (remoteTag !== null) {
      throw new Error(`immutable release tag ${coordinates.tag} already exists remotely`)
    }
  } else {
    if (tag !== coordinates.tag || !/^[0-9a-f]{40}$/.test(commit ?? '')) {
      throw new Error('tagged release context does not match the exact package version and commit')
    }
    if (remoteTag === null) throw new Error('the exact immutable release tag is missing remotely')
    const [headCommit, tagCommit, remoteCommit] = await Promise.all([
      exactLocalCommit(git, cwd, 'HEAD', 'HEAD'),
      exactLocalCommit(git, cwd, `refs/tags/${coordinates.tag}`, 'release tag'),
      resolveGithubTagCommit(fetcher, remoteTag),
    ])
    if (headCommit !== commit || tagCommit !== commit || remoteCommit !== commit) {
      throw new Error('release tag, HEAD, remote tag, and workflow commit are not identical')
    }
  }

  return { ...coordinates, mode }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const mode = process.argv[2]
  const tag = process.argv[3]
  const commit = process.argv[4]
  process.stdout.write(`${JSON.stringify(await releasePreflight({ mode, tag, commit }))}\n`)
}
