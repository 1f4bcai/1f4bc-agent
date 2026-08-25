import { readFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const manifest = JSON.parse(await readFile(resolve(packageRoot, 'package.json'), 'utf8'))

const tag = process.argv[2]
const commit = process.argv[3]
const expectedTag = `agent-v${manifest.version}`

if (tag !== expectedTag) {
  throw new Error(`release tag must exactly match package version: expected ${expectedTag}`)
}
if (!/^[0-9a-f]{40}$/.test(commit ?? '')) {
  throw new Error('release commit must be a full lowercase Git SHA')
}
if (manifest.repository?.url !== 'git+https://github.com/1f4bcai/1f4bc-agent.git') {
  throw new Error('package repository metadata does not match the trusted publisher repository')
}
if (
  process.env.GITHUB_ACTIONS === 'true' &&
  process.env.GITHUB_REPOSITORY !== '1f4bcai/1f4bc-agent'
) {
  throw new Error('provenance release workflow must run from public 1f4bcai/1f4bc-agent')
}

process.stdout.write(`${JSON.stringify({ tag, commit, package: manifest.name, version: manifest.version })}\n`)
