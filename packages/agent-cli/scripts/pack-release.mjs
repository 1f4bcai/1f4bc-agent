import { execFile } from 'node:child_process'
import { mkdir, readdir, writeFile } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import { validateReleaseTarball } from './validate-release-tarball.mjs'

const execFileAsync = promisify(execFile)
const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')

function argumentsMap(argv) {
  const result = new Map()
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index]
    const value = argv[index + 1]
    if (!key?.startsWith('--') || value === undefined) throw new Error(`invalid argument ${key ?? ''}`)
    result.set(key.slice(2), value)
  }
  return result
}

const args = argumentsMap(process.argv.slice(2))
const output = args.get('output')
if (!output) throw new Error('--output is required')
const outputDirectory = resolve(output)
await mkdir(outputDirectory, { recursive: true })
if ((await readdir(outputDirectory)).length !== 0) {
  throw new Error(`release output directory must be empty: ${outputDirectory}`)
}

const gitCommit = args.get('git-commit')
if (!gitCommit || !/^[0-9a-f]{40}$/.test(gitCommit)) {
  throw new Error('--git-commit must be a full lowercase Git commit SHA')
}
const { stdout: headOutput } = await execFileAsync('git', ['rev-parse', 'HEAD'], {
  cwd: packageRoot,
})
if (headOutput.trim() !== gitCommit) throw new Error('--git-commit differs from checked-out HEAD')
const { stdout: statusOutput } = await execFileAsync(
  'git',
  ['status', '--porcelain', '--untracked-files=all'],
  { cwd: packageRoot },
)
if (statusOutput.trim() !== '') throw new Error('release checkout must be clean before packing')

// The final artifact always starts from a clean rebuild performed inside this
// command. Anything that modified ignored dist/ after tests or an earlier
// build is deleted by the package build before npm pack can observe it.
await execFileAsync('npm', ['run', 'build'], {
  cwd: packageRoot,
  maxBuffer: 10 * 1024 * 1024,
})
const { stdout: rebuiltHead } = await execFileAsync('git', ['rev-parse', 'HEAD'], {
  cwd: packageRoot,
})
if (rebuiltHead.trim() !== gitCommit) throw new Error('clean build changed the checked-out commit')
const { stdout: rebuiltStatus } = await execFileAsync(
  'git',
  ['status', '--porcelain', '--untracked-files=all'],
  { cwd: packageRoot },
)
if (rebuiltStatus.trim() !== '') throw new Error('clean build modified tracked release source')

const { stdout, stderr } = await execFileAsync(
  'npm',
  ['pack', '--ignore-scripts', '--json', '--pack-destination', outputDirectory],
  { cwd: packageRoot, maxBuffer: 2 * 1024 * 1024 },
)
if (stderr) process.stderr.write(stderr)
const pack = JSON.parse(stdout)
if (!Array.isArray(pack) || pack.length !== 1) throw new Error('npm pack did not return one package')

await writeFile(join(outputDirectory, 'npm-pack.json'), `${JSON.stringify(pack, null, 2)}\n`)
const release = await validateReleaseTarball({
  tarballPath: join(outputDirectory, pack[0].filename),
  packResult: pack[0],
})
const manifest = { ...release, source: { gitCommit } }
await writeFile(
  join(outputDirectory, 'release-manifest.json'),
  `${JSON.stringify(manifest, null, 2)}\n`,
)
process.stdout.write(`${JSON.stringify(manifest, null, 2)}\n`)
