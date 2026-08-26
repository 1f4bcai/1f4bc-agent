import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  RELEASE_BUILD_PACKAGES,
  assertReleaseBuildPolicy,
  checkReleaseDependencies,
  developmentDependencyClosure,
  requiresProvenance,
  resolveLockedDependency,
  runtimeDependencyClosure,
  verifyInstalledDependencyRecords,
} from '../scripts/check-release-dependencies.mjs'

function expectInOrder(text: string, values: string[]) {
  let cursor = -1
  for (const value of values) {
    const next = text.indexOf(value, cursor + 1)
    expect(next, `missing or out-of-order workflow token: ${value}`).toBeGreaterThan(cursor)
    cursor = next
  }
}

function expectCheckoutCredentialsDisabled(workflow: string) {
  const checkout = 'uses: actions/checkout@'
  let cursor = workflow.indexOf(checkout)
  expect(cursor).toBeGreaterThanOrEqual(0)
  while (cursor >= 0) {
    const nextStep = workflow.indexOf('\n      - name:', cursor + checkout.length)
    const block = workflow.slice(cursor, nextStep < 0 ? workflow.length : nextStep)
    expect(block).toContain('persist-credentials: false')
    cursor = workflow.indexOf(checkout, cursor + checkout.length)
  }
}

function expectCheckoutFullHistory(workflow: string) {
  const checkout = 'uses: actions/checkout@'
  let cursor = workflow.indexOf(checkout)
  expect(cursor).toBeGreaterThanOrEqual(0)
  while (cursor >= 0) {
    const nextStep = workflow.indexOf('\n      - name:', cursor + checkout.length)
    const block = workflow.slice(cursor, nextStep < 0 ? workflow.length : nextStep)
    expect(block).toContain('fetch-depth: 0')
    cursor = workflow.indexOf(checkout, cursor + checkout.length)
  }
}

describe('release dependency closure', () => {
  it('walks each physical runtime package and forbids lifecycle scripts', async () => {
    const lock = JSON.parse(
      await readFile(new URL('../../../package-lock.json', import.meta.url), 'utf8'),
    )
    const closure = runtimeDependencyClosure(lock)
    const paths = closure.map((record) => record.lockPath)

    expect(closure.length).toBeGreaterThan(30)
    expect(paths).toEqual(expect.arrayContaining([
      'node_modules/@modelcontextprotocol/server',
      'node_modules/@x402/fetch',
      'node_modules/viem',
      'node_modules/@x402/core/node_modules/zod',
    ]))
    expect(new Set(paths).size).toBe(paths.length)
    expect(closure.every((record) => record.entry.hasInstallScript !== true)).toBe(true)
    expect(RELEASE_BUILD_PACKAGES).toEqual(['esbuild', '@esbuild/linux-x64'])
  })

  it('walks the complete executable build and test dependency closure', async () => {
    const lock = JSON.parse(
      await readFile(new URL('../../../package-lock.json', import.meta.url), 'utf8'),
    )
    const manifest = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'))
    const closure = developmentDependencyClosure(lock, manifest)
    const paths = closure.map((record) => record.lockPath)
    expect(closure.length).toBeGreaterThan(50)
    expect(paths).toEqual(expect.arrayContaining([
      'node_modules/typescript',
      'node_modules/vitest',
      'node_modules/vite',
      'node_modules/rolldown',
    ]))
    expect(new Set(paths).size).toBe(paths.length)
  })

  it('resolves a nested locked copy before a hoisted copy', () => {
    const packages = {
      'node_modules/dependency': { version: '1.0.0' },
      'node_modules/parent/node_modules/dependency': { version: '2.0.0' },
    }
    expect(resolveLockedDependency(packages, 'node_modules/parent', 'dependency')).toBe(
      'node_modules/parent/node_modules/dependency',
    )
  })

  it('requires SLSA provenance for every explicitly executable build package', () => {
    expect(requiresProvenance({ production: false, direct: false, releaseBuild: true })).toBe(true)
    expect(requiresProvenance({ production: true, direct: true })).toBe(true)
    expect(requiresProvenance({ production: true, direct: false })).toBe(false)
  })

  it('validates registry URL and integrity for every duplicate physical lock record', async () => {
    const manifest = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'))
    const original = JSON.parse(
      await readFile(new URL('../../../package-lock.json', import.meta.url), 'utf8'),
    )
    const lock = structuredClone(original)
    const target = 'node_modules/@x402/evm/node_modules/zod'
    expect(lock.packages[target]?.version).toBe('3.25.76')
    lock.packages[target].resolved = 'https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz'
    lock.packages[target].integrity = `sha512-${Buffer.alloc(64, 9).toString('base64')}`

    const metadata = new Map<string, unknown>()
    const histories = new Map<string, { name: string; time: Record<string, string> }>()
    for (const [lockPath, entry] of Object.entries(original.packages) as Array<[
      string,
      { version?: string; resolved?: string; integrity?: string },
    ]>) {
      const marker = 'node_modules/'
      const offset = lockPath.lastIndexOf(marker)
      if (offset < 0 || !entry.version || !entry.resolved || !entry.integrity) continue
      const name = lockPath.slice(offset + marker.length)
      const versionUrl = `https://registry.npmjs.org/${encodeURIComponent(name)}/${encodeURIComponent(entry.version)}`
      if (!metadata.has(versionUrl)) {
        metadata.set(versionUrl, {
          name,
          version: entry.version,
          dist: {
            integrity: entry.integrity,
            tarball: entry.resolved,
            signatures: [{}],
            attestations: { provenance: { predicateType: 'https://slsa.dev/provenance/v1' } },
          },
        })
      }
      const historyUrl = `https://registry.npmjs.org/${encodeURIComponent(name)}`
      const history = histories.get(historyUrl) ?? { name, time: {} }
      history.time[entry.version] = '2020-01-01T00:00:00.000Z'
      histories.set(historyUrl, history)
    }
    const fetcher = async (input: string | URL | Request) => {
      const url = String(input)
      const body = metadata.get(url) ?? histories.get(url)
      return body
        ? new Response(JSON.stringify(body), { status: 200 })
        : new Response('not found', { status: 404 })
    }

    await expect(checkReleaseDependencies({
      lock,
      manifest,
      minimumAgeHours: 24,
      fetcher: fetcher as typeof fetch,
    })).rejects.toThrow(/@x402\/evm\/node_modules\/zod registry (?:integrity|tarball URL) differs/i)
  })

  it('rejects an installed package whose identity differs from its physical lock path', async () => {
    const root = await mkdtemp(join(tmpdir(), '1f4bc-installed-identity-'))
    try {
      const directory = join(root, 'node_modules', '@x402', 'evm', 'node_modules', 'zod')
      await mkdir(directory, { recursive: true })
      await writeFile(
        join(directory, 'package.json'),
        `${JSON.stringify({ name: 'is-number', version: '7.0.0' })}\n`,
      )
      await expect(verifyInstalledDependencyRecords([{
        lockPath: 'node_modules/@x402/evm/node_modules/zod',
        name: 'zod',
        entry: { version: '3.25.76' },
        direct: false,
        production: true,
      }], root)).rejects.toThrow(/installed package identity differs/i)
    } finally {
      await rm(root, { recursive: true, force: true })
    }
  })

  it('requires the release platform binary even when npm marks it optional', async () => {
    const root = await mkdtemp(join(tmpdir(), '1f4bc-missing-release-platform-'))
    try {
      await expect(verifyInstalledDependencyRecords([{
        lockPath: 'node_modules/@esbuild/linux-x64',
        name: '@esbuild/linux-x64',
        entry: { version: '0.28.1', optional: true },
        direct: false,
        production: false,
        releaseBuild: true,
        required: true,
      }], root)).rejects.toThrow(/missing from the installed dependency tree/i)
    } finally {
      await rm(root, { recursive: true, force: true })
    }
  })

  it('rejects negative or extra release-platform constraints', async () => {
    const lock = JSON.parse(
      await readFile(new URL('../../../package-lock.json', import.meta.url), 'utf8'),
    )
    const tainted = structuredClone(lock)
    tainted.packages['node_modules/@esbuild/linux-x64'].os = ['linux', '!linux']
    const records = RELEASE_BUILD_PACKAGES.map((name) => ({
      lockPath: `node_modules/${name}`,
      name,
      entry: tainted.packages[`node_modules/${name}`],
      direct: false,
      production: false,
      releaseBuild: true,
      required: true,
    }))
    const failures: string[] = []
    assertReleaseBuildPolicy(tainted, records, failures)
    expect(failures).toContain('@esbuild/linux-x64 platform constraints must be exactly linux/x64')
  })
})

describe('release workflow execution order', () => {
  it('pins candidate verification to old main and grants only the release App an atomic push', async () => {
    const workflow = await readFile(
      new URL('../../../.github/workflows/promote-agent-cli-candidate.yml', import.meta.url),
      'utf8',
    )
    expect(workflow).toContain('types: [promote-agent-candidate]')
    expect(workflow).not.toContain('workflow_dispatch:')
    expect(workflow).toContain('cancel-in-progress: false')
    expectInOrder(workflow, [
      'authorize-release-app:',
      'EXPECTED_RELEASE_APP_ACTOR: ${{ vars.RELEASE_APP_ACTOR }}',
      'EXPECTED_RELEASE_APP_ACTOR_ID: ${{ vars.RELEASE_APP_ACTOR_ID }}',
      'test "${GITHUB_ACTOR}" = "${EXPECTED_RELEASE_APP_ACTOR}"',
      'test "${GITHUB_ACTOR_ID}" = "${EXPECTED_RELEASE_APP_ACTOR_ID}"',
      'test "${GITHUB_TRIGGERING_ACTOR}" = "${EXPECTED_RELEASE_APP_ACTOR}"',
      'verify-candidate:',
      'ref: ${{ github.sha }}',
      'fetch-depth: 1',
      'persist-credentials: false',
      'promote-release-candidate.mjs verify',
      'promote-candidate:',
      'Reverify before requesting any write authority',
      'uses: actions/create-github-app-token@',
      'permission-contents: write',
      'promote-release-candidate.mjs promote',
    ])
    expect(workflow.match(/promote-release-candidate\.mjs verify/g)).toHaveLength(2)
    expect(workflow.match(/ref: \$\{\{ github\.sha \}\}/g)).toHaveLength(2)
    expect(workflow.match(/persist-credentials: false/g)).toHaveLength(2)
    expect(workflow).toContain('RELEASE_APP_PRIVATE_KEY')
    expect(workflow).toContain('RELEASE_APP_ID')
    expect(workflow).not.toContain('ref: ${{ github.event.client_payload.candidate_ref }}')
    expect(workflow).not.toMatch(/uses:\s+[^\s]+@v\d/)
    expect(workflow).not.toContain('npm ')
    expect(workflow).not.toContain('id-token: write')
  })

  it('gates all dependencies before the only allowlisted native setup', async () => {
    const workflows = await Promise.all([
      readFile(
        new URL('../../../.github/workflows/agent-cli-public-ci.yml', import.meta.url),
        'utf8',
      ),
    ])

    for (const workflow of workflows) {
      expectCheckoutCredentialsDisabled(workflow)
      expect(workflow).not.toContain('ubuntu-latest')
      expectInOrder(workflow, [
        'npm ci --ignore-scripts',
        'npm audit signatures --ignore-scripts',
        'check-release-dependencies.mjs',
        'npm rebuild esbuild --foreground-scripts',
      ])
      expect(workflow).not.toMatch(/uses:\s+[^\s]+@v\d/)
    }
  })

  it('keeps all tagged code out of the minimal stage-only OIDC job', async () => {
    const workflow = await readFile(
      new URL('../../../.github/workflows/release-agent-cli.yml', import.meta.url),
      'utf8',
    )
    const authorizationStart = workflow.indexOf('  authorize-release-app:')
    const testStart = workflow.indexOf('  test-reviewed-source:')
    const buildStart = workflow.indexOf('  build-reviewed-artifact:')
    const verifyStart = workflow.indexOf('  independent-rebuild-verification:')
    const consumerStart = workflow.indexOf('  exact-artifact-consumer-verification:')
    const stageStart = workflow.indexOf('  stage-reviewed-artifact:')
    const authorizationJob = workflow.slice(authorizationStart, testStart)
    const testJob = workflow.slice(testStart, buildStart)
    const buildJob = workflow.slice(buildStart, verifyStart)
    const verifyJob = workflow.slice(verifyStart, consumerStart)
    const consumerJob = workflow.slice(consumerStart, stageStart)
    const stageJob = workflow.slice(stageStart)

    expectCheckoutCredentialsDisabled(workflow)
    expectCheckoutFullHistory(workflow)
    expect(workflow).not.toContain('ubuntu-latest')
    expect(authorizationStart).toBeGreaterThanOrEqual(0)
    expectInOrder(authorizationJob, [
      'EXPECTED_RELEASE_APP_ACTOR: ${{ vars.RELEASE_APP_ACTOR }}',
      'EXPECTED_RELEASE_APP_ACTOR_ID: ${{ vars.RELEASE_APP_ACTOR_ID }}',
      'test -n "${EXPECTED_RELEASE_APP_ACTOR}"',
      'test -n "${EXPECTED_RELEASE_APP_ACTOR_ID}"',
      'test "${GITHUB_ACTOR}" = "${EXPECTED_RELEASE_APP_ACTOR}"',
      'test "${GITHUB_ACTOR_ID}" = "${EXPECTED_RELEASE_APP_ACTOR_ID}"',
      'test "${GITHUB_TRIGGERING_ACTOR}" = "${EXPECTED_RELEASE_APP_ACTOR}"',
    ])
    expect(authorizationJob).not.toContain('actions/checkout')
    expect(testJob).toContain('needs: authorize-release-app')
    for (const guardedJob of [testJob, buildJob, verifyJob, consumerJob, stageJob]) {
      expect(guardedJob).toContain("vars.RELEASE_APP_ACTOR != ''")
      expect(guardedJob).toContain("vars.RELEASE_APP_ACTOR_ID != ''")
      expect(guardedJob).toContain('github.actor == vars.RELEASE_APP_ACTOR')
      expect(guardedJob).toContain('github.actor_id == vars.RELEASE_APP_ACTOR_ID')
      expect(guardedJob).toContain('github.triggering_actor == vars.RELEASE_APP_ACTOR')
    }
    expect(workflow.match(/npm ci --ignore-scripts/g)).toHaveLength(3)
    expect(workflow.match(/npm audit signatures --ignore-scripts/g)).toHaveLength(3)
    expect(workflow.match(/check-release-dependencies\.mjs/g)).toHaveLength(3)
    expect(workflow.match(/release-preflight\.mjs tagged-ci/g)).toHaveLength(3)
    expect(workflow.match(/verify-public-tree\.mjs/g)).toHaveLength(3)
    expect(workflow.match(/git rev-parse origin\/main/g)).toHaveLength(3)
    expect(workflow).not.toContain('merge-base --is-ancestor')
    expect(workflow.match(/npm rebuild esbuild --foreground-scripts/g)).toHaveLength(3)
    expect(workflow.match(/npm test --workspace=@1f4bcai\/agent/g)).toHaveLength(1)
    expect(testJob).toContain('npm test --workspace=@1f4bcai/agent')
    expect(testJob).toContain('generate-release-sbom.mjs')
    expect(buildJob).not.toContain('id-token: write')
    expect(buildJob).not.toContain('npm test')
    expect(buildJob).not.toContain('generate-release-sbom.mjs')
    expect(verifyJob).not.toContain('id-token: write')
    expect(verifyJob).not.toContain('npm test')
    expect(verifyJob).not.toContain('generate-release-sbom.mjs')
    expectInOrder(verifyJob, [
      'npm ci --ignore-scripts',
      'npm audit signatures --ignore-scripts',
      'check-release-dependencies.mjs',
      'npm rebuild esbuild --foreground-scripts',
      'pack-release.mjs',
      'Download the reviewed bundle',
      'cmp --silent',
    ])
    expect(consumerJob).not.toContain('id-token: write')
    expect(consumerJob).not.toContain('actions/checkout')
    expect(consumerJob).not.toContain('upload-artifact')
    expect(consumerJob).not.toContain('node packages/')
    expect(consumerJob).toContain('Download and verify the original reviewed artifact')
    expect(consumerJob).toContain('ARTIFACT_ID: ${{ needs.build-reviewed-artifact.outputs.artifact_id }}')
    expect(consumerJob).toContain('TARBALL_SHA512: ${{ needs.build-reviewed-artifact.outputs.tarball_sha512 }}')
    expect(consumerJob).toContain('--ignore-scripts --offline')
    expect(consumerJob).toContain('NODE20_ARCHIVE_SHA256')
    expect(consumerJob).toContain('node-v20.3.0-linux-x64')
    expect(consumerJob.match(/dist\/index\.js --help/g)).toHaveLength(2)
    expect(consumerJob).toContain("grep -F 'pay <https-url> --amount-atomic N --pay-to 0x...' \"${help}\"")
    expect(consumerJob).toContain("cat > verify-imports.mjs <<'NODE'")
    expect(consumerJob).toContain('"${node_bin}" verify-imports.mjs')
    expect(consumerJob).toContain('"${node20_bin}" verify-imports.mjs')
    expect(consumerJob).toContain("'@1f4bcai/agent/terminal-clear'")
    expect(consumerJob).toContain("'@1f4bcai/agent/dist/runtime.js'")
    expect(consumerJob).toContain("ERR_PACKAGE_PATH_NOT_EXPORTED")
    expect(consumerJob).toContain('TYPESCRIPT_LINUX_X64_TARBALL_SHA512')
    expect(consumerJob).toContain('@typescript/typescript-linux-x64/-/typescript-linux-x64-7.0.2.tgz')
    expect(consumerJob).toContain('${compiler_modules}/@typescript/typescript-linux-x64')
    expect(consumerJob).toContain('consumer-compiler/node_modules/typescript/lib/tsc.js')
    expect(consumerJob).toContain("printf 'verified_sha512=%s\\n'")
    expectInOrder(stageJob, [
      'environment: npm-agent-release',
      'id-token: write',
      'Download and verify the reviewed GitHub artifact',
      'NODE_ARCHIVE_SHA256',
      'registry_status=',
      '"${NODE_BIN}" "${NPM_CLI}" stage publish',
    ])
    expect(stageJob).not.toContain('uses:')
    expect(stageJob).not.toContain('actions/checkout')
    expect(stageJob).not.toContain('actions/setup-node')
    expect(stageJob).not.toContain('npm ci')
    expect(stageJob).not.toContain('npm run')
    expect(stageJob).not.toContain('npm test')
    expect(stageJob).not.toContain('node packages/')
    expect(stageJob).toContain('exact-artifact-consumer-verification')
    expect(stageJob).toContain('test "${TARBALL_SHA512}" = "${CONSUMER_SHA512}"')
    expect(stageJob).toContain('https://registry.npmjs.org/%401f4bcai%2Fagent/${version}')
    expect(stageJob).toContain('test "${registry_status}" = \'404\'')
    expect(stageJob).not.toMatch(/\bnpm(?:")?\s+publish\b/)
    expect(stageJob).toContain("-p 'process.execPath'")
    expect(stageJob).toContain('"${NODE_BIN}" "${NPM_CLI}" stage publish')
    expect(stageJob).toContain('--ignore-scripts')
    expect(stageJob).toContain('--provenance')
    expect(workflow).not.toMatch(/uses:\s+[^\s]+@v\d/)
  })

  it('always discards post-test dist mutations before final packing', async () => {
    const [script, manifest] = await Promise.all([
      readFile(new URL('../scripts/pack-release.mjs', import.meta.url), 'utf8'),
      readFile(new URL('../package.json', import.meta.url), 'utf8'),
    ])
    expectInOrder(script, [
      "['status', '--porcelain', '--untracked-files=all']",
      "['run', 'build']",
      "['pack', '--ignore-scripts'",
    ])
    expect(JSON.parse(manifest).scripts.build).toMatch(/^node scripts\/clean-dist\.mjs &&/)
  })

  it('uses snapshot verification only for PRs and authenticated candidate pushes', async () => {
    const [workflow, releaseWorkflow] = await Promise.all([
      readFile(
      new URL('../../../.github/workflows/agent-cli-public-ci.yml', import.meta.url),
      'utf8',
      ),
      readFile(
        new URL('../../../.github/workflows/release-agent-cli.yml', import.meta.url),
        'utf8',
      ),
    ])
    expectCheckoutCredentialsDisabled(workflow)
    expect(workflow).toContain(
      "fetch-depth: ${{ (github.event_name == 'pull_request' || startsWith(github.ref, 'refs/heads/agent-candidate-')) && 1 || 0 }}",
    )
    expectInOrder(workflow, [
      '- name: Check out public source',
      'ref: ${{ github.sha }}',
      "fetch-depth: ${{ (github.event_name == 'pull_request' || startsWith(github.ref, 'refs/heads/agent-candidate-')) && 1 || 0 }}",
      'persist-credentials: false',
      '- name: Remove checkout\'s inert worktree config compatibility file',
      '- name: Prove the candidate checkout is exact, detached, and tracking-free',
      'test "$(git rev-parse --verify HEAD^{commit})" = "${GITHUB_SHA}"',
      'test "${symbolic_head_status}" -eq 1',
      'test "${candidate_remote_status}" -eq 1',
      'test "${candidate_merge_status}" -eq 1',
      'test "${candidate_config_status}" -eq 1',
      'test ! -s "${candidate_config_output}"',
    ])
    expect(workflow.match(/uses: actions\/checkout@/g)).toHaveLength(1)
    expect(workflow.match(/ref: \$\{\{ github\.sha \}\}/g)).toHaveLength(1)
    expect(workflow.match(/persist-credentials: false/g)).toHaveLength(1)
    expect(workflow).not.toContain('git config --global')
    expect(workflow).not.toContain('git config --unset')
    expect(workflow).toContain('repository_dispatch:')
    expect(workflow).toContain('types: [bootstrap-ci]')
    expect(workflow).not.toContain('workflow_dispatch:')
    expectInOrder(workflow, [
      '- name: Authorize the release App bootstrap dispatch',
      "if: github.event_name == 'repository_dispatch'",
      'EXPECTED_RELEASE_APP_ACTOR: ${{ vars.RELEASE_APP_ACTOR }}',
      'EXPECTED_RELEASE_APP_ACTOR_ID: ${{ vars.RELEASE_APP_ACTOR_ID }}',
      'test -n "${EXPECTED_RELEASE_APP_ACTOR}"',
      'test -n "${EXPECTED_RELEASE_APP_ACTOR_ID}"',
      'test "${GITHUB_ACTOR}" = "${EXPECTED_RELEASE_APP_ACTOR}"',
      'test "${GITHUB_ACTOR_ID}" = "${EXPECTED_RELEASE_APP_ACTOR_ID}"',
      'test "${GITHUB_TRIGGERING_ACTOR}" = "${EXPECTED_RELEASE_APP_ACTOR}"',
      '- name: Check out public source',
    ])
    expect(workflow).toContain("startsWith(github.ref, 'refs/heads/agent-candidate-')")
    expect(workflow).toContain('- name: Authorize the release App candidate push')
    expect(workflow).toContain("if: startsWith(github.ref, 'refs/heads/agent-candidate-')")
    expect(workflow).toContain('test "${GITHUB_SHA:0:12}" = "${candidate_ref##*-}"')
    expectInOrder(workflow, [
      '- name: Authorize the release App candidate push',
      'test "${GITHUB_EVENT_NAME}" = "push"',
      'test "${GITHUB_ACTOR}" = "${EXPECTED_RELEASE_APP_ACTOR}"',
      'test "${GITHUB_ACTOR_ID}" = "${EXPECTED_RELEASE_APP_ACTOR_ID}"',
      'test "${GITHUB_TRIGGERING_ACTOR}" = "${EXPECTED_RELEASE_APP_ACTOR}"',
      'test "${GITHUB_SHA:0:12}" = "${candidate_ref##*-}"',
      '- name: Check out public source',
      '- name: Bind the candidate ref to the checked-out package version',
      'verify-public-tree.mjs --snapshot-only',
      'npm ci --ignore-scripts',
      'npm audit signatures --ignore-scripts',
      'npm rebuild esbuild --foreground-scripts',
      'npm test --workspace=@1f4bcai/agent',
    ])
    expect(workflow).toContain("if: github.event_name == 'pull_request' || startsWith(github.ref, 'refs/heads/agent-candidate-')")
    expect(workflow).toContain("if: github.event_name != 'pull_request' && !startsWith(github.ref, 'refs/heads/agent-candidate-')")
    expect(workflow).not.toContain('contents: write')
    expect(workflow).not.toContain('secrets.')
    expect(workflow.match(/verify-public-tree\.mjs --snapshot-only/g)).toHaveLength(1)
    expect(workflow.match(/verify-public-tree\.mjs(?:\s|$)/g)).toHaveLength(2)
    expect(releaseWorkflow).not.toContain('--snapshot-only')
    expect(releaseWorkflow.match(/verify-public-tree\.mjs/g)).toHaveLength(3)
  })
})
