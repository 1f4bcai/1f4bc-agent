import { createHash } from 'node:crypto'
import { lstat, readFile, readdir } from 'node:fs/promises'
import { dirname, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  EXPECTED_PACKAGE_FILES,
  validateReleaseDirectory,
} from './validate-release-tarball.mjs'

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')

function sha512(buffer) {
  return `sha512-${createHash('sha512').update(buffer).digest('base64')}`
}

function safePackagePath(root, path) {
  const absolute = resolve(root, ...path.split('/'))
  const within = relative(root, absolute)
  if (within === '..' || within.startsWith(`..${sep}`)) {
    throw new Error(`independent rebuild path escaped package root: ${path}`)
  }
  return absolute
}

async function listFiles(root, directory = root) {
  const paths = []
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const absolute = resolve(directory, entry.name)
    if (entry.isSymbolicLink()) throw new Error(`independent rebuild contains symlink: ${absolute}`)
    if (entry.isDirectory()) paths.push(...await listFiles(root, absolute))
    else if (entry.isFile()) paths.push(relative(root, absolute).split(sep).join('/'))
    else throw new Error(`independent rebuild contains non-file entry: ${absolute}`)
  }
  return paths
}

export async function compareReviewedBuild({
  releaseDirectory,
  expectedCommit,
  sourcePackageRoot = packageRoot,
}) {
  const release = await validateReleaseDirectory(releaseDirectory, expectedCommit)
  const reviewedByPath = new Map(release.files.map((file) => [file.path, file]))
  const expectedPaths = [...EXPECTED_PACKAGE_FILES.keys()].sort()
  if (JSON.stringify([...reviewedByPath.keys()].sort()) !== JSON.stringify(expectedPaths)) {
    throw new Error('reviewed release file list changed before independent rebuild comparison')
  }

  const independentlyBuiltDist = (await listFiles(
    resolve(sourcePackageRoot, 'dist'),
  )).map((path) => `dist/${path}`).sort()
  const expectedDist = expectedPaths.filter((path) => path.startsWith('dist/'))
  if (JSON.stringify(independentlyBuiltDist) !== JSON.stringify(expectedDist)) {
    throw new Error('independent rebuild dist file list differs from the reviewed release')
  }

  for (const path of expectedPaths) {
    const reviewed = reviewedByPath.get(path)
    const absolute = safePackagePath(sourcePackageRoot, path)
    const stat = await lstat(absolute)
    if (!stat.isFile() || stat.nlink !== 1) {
      throw new Error(`independent rebuild output is not one regular file: ${path}`)
    }
    const content = await readFile(absolute)
    const mode = stat.mode & 0o777
    if (
      content.byteLength !== reviewed.size ||
      mode !== reviewed.mode ||
      sha512(content) !== reviewed.sha512
    ) {
      throw new Error(`independent rebuild differs from reviewed release: ${path}`)
    }
  }

  return {
    package: release.package,
    sourceCommit: release.source.gitCommit,
    comparedFiles: expectedPaths.length,
  }
}

const invokedPath = process.argv[1] ? resolve(process.argv[1]) : undefined
if (invokedPath === fileURLToPath(import.meta.url)) {
  const releaseDirectory = process.argv[2]
  const expectedCommit = process.argv[3]
  if (!releaseDirectory || !expectedCommit) {
    throw new Error('usage: verify-independent-rebuild.mjs <release-directory> <git-commit>')
  }
  const result = await compareReviewedBuild({ releaseDirectory, expectedCommit })
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`)
}
