import { describe, expect, it } from 'vitest'
import {
  releasePreflight,
  type ReleasePreflightGit,
} from '../scripts/release-preflight.mjs'

const commit = 'a'.repeat(40)
const packageName = '@1f4bcai/agent'
const version = '0.1.3'
const tag = `agent-v${version}`
const manifest = {
  name: packageName,
  version,
  repository: { url: 'git+https://github.com/1f4bcai/1f4bc-agent.git' },
}

function registryUrl() {
  return `https://registry.npmjs.org/${encodeURIComponent(packageName)}/${version}`
}

function tagUrl() {
  return `https://api.github.com/repos/1f4bcai/1f4bc-agent/git/ref/tags/${tag}`
}

function fetchStatuses(entries: Record<string, () => Response>): typeof fetch {
  return (async (input: string | URL | Request) => {
    const response = entries[String(input)]
    return response?.() ?? new Response('unexpected URL', { status: 500 })
  }) as typeof fetch
}

function gitResults(entries: Record<string, { status: number; stdout?: string }>): ReleasePreflightGit {
  return async (args) => {
    const key = args.join(' ')
    const result = entries[key]
    if (!result) return { status: 127, stdout: '' }
    return { status: result.status, stdout: result.stdout ?? '' }
  }
}

function availableFetcher(remote = () => new Response('', { status: 404 })) {
  return fetchStatuses({
    [registryUrl()]: () => new Response('', { status: 404 }),
    [tagUrl()]: remote,
  })
}

describe('immutable release availability preflight', () => {
  it.each(['0.1.0', '0.1.1', '0.1.2'])(
    'rejects retired release version %s before any availability request',
    async (retiredVersion) => {
      await expect(releasePreflight({
        mode: 'prepare',
        manifest: { ...manifest, version: retiredVersion },
        fetcher: (() => {
          throw new Error('retired versions must not reach the network')
        }) as typeof fetch,
      })).rejects.toThrow(/retired release version/i)
    },
  )

  it('permits prepare only when the npm version and exact tag are both unused', async () => {
    await expect(releasePreflight({
      mode: 'prepare',
      manifest,
      fetcher: availableFetcher(),
      git: gitResults({
        [`show-ref --verify --quiet refs/tags/${tag}`]: { status: 1 },
      }),
    })).resolves.toEqual({ packageName, version, tag, mode: 'prepare' })
  })

  it.each(['prepare', 'tagged-ci'] as const)(
    'rejects an already-published exact npm version in %s mode',
    async (mode) => {
      const fetcher = fetchStatuses({
        [registryUrl()]: () => new Response(JSON.stringify({ name: packageName, version }), {
          status: 200,
        }),
      })
      await expect(releasePreflight({ mode, manifest, tag, commit, fetcher }))
        .rejects.toThrow(/already published/i)
    },
  )

  it('rejects an exact immutable tag that already exists locally or remotely', async () => {
    await expect(releasePreflight({
      mode: 'prepare',
      manifest,
      fetcher: availableFetcher(),
      git: gitResults({
        [`show-ref --verify --quiet refs/tags/${tag}`]: { status: 0 },
      }),
    })).rejects.toThrow(/already exists locally/i)

    await expect(releasePreflight({
      mode: 'prepare',
      manifest,
      fetcher: availableFetcher(() => new Response(JSON.stringify({
        ref: `refs/tags/${tag}`,
        object: { type: 'commit', sha: commit },
      }), { status: 200 })),
      git: gitResults({
        [`show-ref --verify --quiet refs/tags/${tag}`]: { status: 1 },
      }),
    })).rejects.toThrow(/already exists remotely/i)
  })

  it('requires the tagged workflow tag, HEAD, remote tag, and workflow SHA to be exact', async () => {
    const fetcher = availableFetcher(() => new Response(JSON.stringify({
      ref: `refs/tags/${tag}`,
      object: { type: 'commit', sha: commit },
    }), { status: 200 }))
    const git = gitResults({
      'rev-parse --verify HEAD^{commit}': { status: 0, stdout: `${commit}\n` },
      [`rev-parse --verify refs/tags/${tag}^{commit}`]: { status: 0, stdout: `${commit}\n` },
    })

    await expect(releasePreflight({
      mode: 'tagged-ci', manifest, tag, commit, fetcher, git,
    })).resolves.toEqual({ packageName, version, tag, mode: 'tagged-ci' })

    await expect(releasePreflight({
      mode: 'tagged-ci',
      manifest,
      tag,
      commit,
      fetcher,
      git: gitResults({
        'rev-parse --verify HEAD^{commit}': { status: 0, stdout: `${'b'.repeat(40)}\n` },
        [`rev-parse --verify refs/tags/${tag}^{commit}`]: { status: 0, stdout: `${commit}\n` },
      }),
    })).rejects.toThrow(/not identical/i)
  })

  it('fails closed when either authoritative availability service is unavailable', async () => {
    await expect(releasePreflight({
      mode: 'prepare',
      manifest,
      fetcher: fetchStatuses({
        [registryUrl()]: () => new Response('', { status: 503 }),
      }),
    })).rejects.toThrow(/failed closed.*503/i)

    await expect(releasePreflight({
      mode: 'prepare',
      manifest,
      fetcher: fetchStatuses({
        [registryUrl()]: () => new Response('', { status: 404 }),
        [tagUrl()]: () => new Response('', { status: 403 }),
      }),
    })).rejects.toThrow(/failed closed.*403/i)
  })
})
