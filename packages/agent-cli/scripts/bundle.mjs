import { createHash } from 'node:crypto'
import { builtinModules } from 'node:module'
import { build } from 'esbuild'
import { readdir, readFile, rm, writeFile } from 'node:fs/promises'
import { basename, dirname, join, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  BUNDLED_RUNTIME_PACKAGES,
  runtimeDependencyClosure,
} from './check-release-dependencies.mjs'

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const repositoryRoot = resolve(packageRoot, '..', '..')
const dist = resolve(packageRoot, 'dist')
const bundleEntries = Object.freeze({
  runtime: resolve(packageRoot, 'src/public-runtime.ts'),
})
const publicEntries = Object.freeze({
  index: resolve(packageRoot, 'src/index.ts'),
  api: resolve(packageRoot, 'src/api.ts'),
  mcp: resolve(packageRoot, 'src/mcp.ts'),
  'mcp-payments': resolve(packageRoot, 'src/mcp-payments.ts'),
  'peer-payments': resolve(packageRoot, 'src/peer-payments.ts'),
})
const declarationNames = new Set(['index', ...Object.keys(publicEntries), 'keys'])
const builtins = new Set([...builtinModules, ...builtinModules.map((name) => `node:${name}`)])

function packageDirectoryForInput(input) {
  let current = dirname(resolve(repositoryRoot, input))
  while (current !== dirname(current)) {
    const parent = dirname(current)
    if (
      basename(parent) === 'node_modules' ||
      (basename(dirname(parent)) === 'node_modules' && basename(parent).startsWith('@'))
    ) {
      return current
    }
    current = parent
  }
  return undefined
}

function repositoryUrl(repository) {
  const value = typeof repository === 'string' ? repository : repository?.url
  if (typeof value !== 'string') return ''
  return value.replace(/[\r\n]/g, '')
}

async function packageLicenseFiles(directory, manifest) {
  const names = (await readdir(directory)).filter((name) =>
    /^(?:licen[sc]e|copying|notice)(?:\..*)?$/i.test(name),
  ).sort()
  if (names.length > 0) {
    return Promise.all(names.map(async (name) => ({
      name,
      text: await readFile(join(directory, name), 'utf8'),
    })))
  }
  const fallback = manifest.license === 'Apache-2.0'
    ? resolve(packageRoot, 'licenses/Apache-2.0.txt')
    : manifest.license === 'MIT'
      ? resolve(packageRoot, 'licenses/MIT.txt')
      : undefined
  if (!fallback) throw new Error(`bundled package at ${directory} has no distributable license text`)
  const files = [{ name: `${manifest.license}.txt`, text: await readFile(fallback, 'utf8') }]
  if (manifest.name.startsWith('@x402/')) {
    if (manifest.version !== '2.23.0') {
      throw new Error(`x402 NOTICE must be re-reviewed for ${manifest.name}@${manifest.version}`)
    }
    files.push({
      name: 'NOTICE',
      text: await readFile(resolve(packageRoot, 'licenses/x402-NOTICE-2.23.0.txt'), 'utf8'),
    })
  }
  return files
}

function lockPathForDirectory(directory) {
  return relative(repositoryRoot, directory).split(sep).join('/')
}

async function bundledPackages(metafiles) {
  const packageDirectories = new Set()
  for (const metafile of metafiles) for (const input of Object.keys(metafile.inputs)) {
    const directory = packageDirectoryForInput(input)
    if (directory) packageDirectories.add(directory)
  }
  const lock = JSON.parse(await readFile(resolve(repositoryRoot, 'package-lock.json'), 'utf8'))
  const allowedPaths = new Set(runtimeDependencyClosure(lock).map((entry) => entry.lockPath))
  const packages = []
  for (const directory of [...packageDirectories].sort()) {
    const manifest = JSON.parse(await readFile(join(directory, 'package.json'), 'utf8'))
    if (
      typeof manifest.name !== 'string' ||
      typeof manifest.version !== 'string' ||
      typeof manifest.license !== 'string'
    ) {
      throw new Error(`bundled package metadata is incomplete at ${directory}`)
    }
    const lockPath = lockPathForDirectory(directory)
    const locked = lock.packages?.[lockPath]
    if (
      locked?.version !== manifest.version ||
      typeof locked.integrity !== 'string' ||
      !locked.integrity.startsWith('sha512-') ||
      typeof locked.resolved !== 'string' ||
      !locked.resolved.startsWith('https://registry.npmjs.org/')
    ) {
      throw new Error(`bundled package is not bound to the audited npm lock: ${lockPath}`)
    }
    if (!allowedPaths.has(lockPath)) {
      throw new Error(`bundle imported a package outside the reviewed runtime closure: ${lockPath}`)
    }
    packages.push({ directory, lockPath, manifest, locked })
  }
  const includedNames = new Set(packages.map(({ manifest }) => manifest.name))
  for (const name of BUNDLED_RUNTIME_PACKAGES) {
    if (!includedNames.has(name)) throw new Error(`bundle omitted declared runtime input ${name}`)
  }
  return { packages, lock }
}

async function thirdPartyNotices(packages) {
  const inventory = []
  const licenseTexts = new Map()
  for (const { directory, manifest } of packages) {
    const id = `${manifest.name}@${manifest.version}`
    const files = await packageLicenseFiles(directory, manifest)
    const licenses = []
    for (const file of files) {
      const text = file.text.replace(/\r\n/g, '\n').trimEnd() + '\n'
      const hash = createHash('sha256').update(text).digest('hex')
      licenses.push(hash)
      const record = licenseTexts.get(hash) ?? { text, packages: [], files: [] }
      record.packages.push(id)
      record.files.push(`${id}/${file.name}`)
      licenseTexts.set(hash, record)
    }
    inventory.push({
      id,
      license: manifest.license,
      repository: repositoryUrl(manifest.repository),
      licenses: [...new Set(licenses)].sort(),
    })
  }

  const lines = [
    'THIRD-PARTY SOFTWARE NOTICES',
    '',
    'The JavaScript distributed by @1f4bcai/agent is self-contained. It includes code',
    'from the packages below; consumers do not resolve or execute runtime dependencies.',
    '',
    'PACKAGE INVENTORY',
    '',
  ]
  for (const entry of inventory.sort((left, right) => left.id.localeCompare(right.id))) {
    lines.push(`- ${entry.id} | ${entry.license} | license text: ${entry.licenses.join(', ')}`)
    if (entry.repository) lines.push(`  Source: ${entry.repository}`)
  }
  lines.push('', 'LICENSE AND NOTICE TEXTS', '')
  for (const [hash, record] of [...licenseTexts].sort(([left], [right]) => left.localeCompare(right))) {
    lines.push(`===== SHA-256 ${hash} =====`)
    lines.push(`Applies to: ${[...new Set(record.packages)].sort().join(', ')}`)
    lines.push(`Source files: ${[...new Set(record.files)].sort().join(', ')}`)
    lines.push('', record.text.trimEnd(), '')
  }
  return `${lines.join('\n').trimEnd()}\n`
}

function packagePurl(name, version) {
  const encoded = name.startsWith('@') ? `%40${name.slice(1)}` : encodeURIComponent(name)
  return `pkg:npm/${encoded}@${encodeURIComponent(version)}`
}

function nearestLockedDependency(lockPackages, parentPath, name) {
  let directory = parentPath
  while (true) {
    const candidate = `${directory ? `${directory}/` : ''}node_modules/${name}`
    if (lockPackages[candidate]) return candidate
    if (!directory) return undefined
    const slash = directory.lastIndexOf('/')
    directory = slash < 0 ? '' : directory.slice(0, slash)
  }
}

function embeddedSbom(manifest, packages, lock) {
  const rootRef = packagePurl(manifest.name, manifest.version)
  const byPath = new Map(packages.map((entry) => [entry.lockPath, entry]))
  const components = packages.map(({ lockPath, manifest: dependency, locked }) => {
    const purl = packagePurl(dependency.name, dependency.version)
    const bomRef = `${purl}?lock_path=${encodeURIComponent(lockPath)}`
    return {
      type: 'library',
      'bom-ref': bomRef,
      ...(dependency.name.startsWith('@')
        ? { group: dependency.name.split('/')[0], name: dependency.name.split('/')[1] }
        : { name: dependency.name }),
      version: dependency.version,
      purl,
      hashes: [{
        alg: 'SHA-512',
        content: Buffer.from(locked.integrity.slice('sha512-'.length), 'base64').toString('hex'),
      }],
      licenses: [{ expression: dependency.license }],
      properties: [
        { name: '1f4bc:lockPath', value: lockPath },
        { name: '1f4bc:npmIntegrity', value: locked.integrity },
      ],
      externalReferences: [
        { type: 'distribution', url: locked.resolved },
        ...(repositoryUrl(dependency.repository)
          ? [{ type: 'vcs', url: repositoryUrl(dependency.repository) }]
          : []),
      ],
    }
  }).sort((left, right) => left['bom-ref'].localeCompare(right['bom-ref']))
  const refByPath = new Map(components.map((component) => [
    component.properties.find((property) => property.name === '1f4bc:lockPath').value,
    component['bom-ref'],
  ]))
  const dependencies = [{
    ref: rootRef,
    dependsOn: components.map((component) => component['bom-ref']),
  }]
  for (const { lockPath, locked } of packages) {
    const childPaths = new Set()
    for (const name of [
      ...Object.keys(locked.dependencies ?? {}),
      ...Object.keys(locked.optionalDependencies ?? {}),
      ...Object.keys(locked.peerDependencies ?? {}).filter(
        (name) => locked.peerDependenciesMeta?.[name]?.optional !== true,
      ),
    ]) {
      const child = nearestLockedDependency(lock.packages, lockPath, name)
      if (child && byPath.has(child)) childPaths.add(child)
    }
    dependencies.push({
      ref: refByPath.get(lockPath),
      dependsOn: [...childPaths].sort().map((path) => refByPath.get(path)),
    })
  }
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    version: 1,
    metadata: {
      component: {
        type: 'application',
        'bom-ref': rootRef,
        group: '@1f4bcai',
        name: 'agent',
        version: manifest.version,
        purl: rootRef,
      },
      properties: [{ name: '1f4bc:vendoredDependencies', value: 'true' }],
    },
    components,
    dependencies: dependencies.sort((left, right) => left.ref.localeCompare(right.ref)),
  }
}

const manifest = JSON.parse(await readFile(resolve(packageRoot, 'package.json'), 'utf8'))
for (const field of [
  'dependencies',
  'optionalDependencies',
  'peerDependencies',
  'bundledDependencies',
  'bundleDependencies',
]) {
  const value = manifest[field]
  const count = Array.isArray(value) ? value.length : Object.keys(value ?? {}).length
  if (count !== 0) throw new Error(`the published CLI must not declare ${field}`)
}

const result = await build({
  absWorkingDir: repositoryRoot,
  entryPoints: bundleEntries,
  outdir: dist,
  entryNames: '[name]',
  bundle: true,
  splitting: false,
  platform: 'node',
  format: 'esm',
  target: ['node20'],
  sourcemap: false,
  sourcesContent: false,
  legalComments: 'eof',
  treeShaking: true,
  metafile: true,
  logLevel: 'warning',
})

for (const output of Object.values(result.metafile.outputs)) {
  for (const imported of output.imports) {
    if (imported.external && !builtins.has(imported.path)) {
      throw new Error(`bundle retained forbidden external import ${imported.path}`)
    }
  }
}

for (const [name, source] of Object.entries(publicEntries)) {
  const analysis = await build({
    absWorkingDir: repositoryRoot,
    entryPoints: [source],
    bundle: false,
    write: false,
    format: 'esm',
    platform: 'node',
    metafile: true,
    logLevel: 'silent',
  })
  const exports = Object.values(analysis.metafile.outputs)[0]?.exports ?? []
  if (exports.length === 0) throw new Error(`public entry ${name} has no runtime exports`)
  const names = [...exports].sort()
  const shim = name === 'index'
    ? `#!/usr/bin/env node
import { realpathSync } from 'node:fs'
import { pathToFileURL } from 'node:url'
import { ${names.join(', ')} } from './runtime.js'
export { ${names.join(', ')} }
const directEntry = (() => {
  if (!process.argv[1]) return ''
  try { return pathToFileURL(realpathSync(process.argv[1])).href }
  catch { return pathToFileURL(process.argv[1]).href }
})()
if (import.meta.url === directEntry) {
  main().catch((error) => {
    process.stderr.write(\`1f4bc: \${error instanceof Error ? error.message : String(error)}\\n\`)
    process.exitCode = 1
  })
}
`
    : `export { ${names.join(', ')} } from './runtime.js'\n`
  await writeFile(
    resolve(dist, `${name}.js`),
    shim,
    { encoding: 'utf8', mode: 0o644 },
  )
}

for (const name of await readdir(dist)) {
  const declaration = name.endsWith('.d.ts') && declarationNames.has(name.slice(0, -5))
  const javascript = name.endsWith('.js') && (
    Object.hasOwn(bundleEntries, name.slice(0, -3)) ||
    Object.hasOwn(publicEntries, name.slice(0, -3))
  )
  if (!declaration && !javascript) await rm(resolve(dist, name), { force: true })
}
const bundled = await bundledPackages([result.metafile])
await writeFile(
  resolve(dist, 'THIRD_PARTY_NOTICES.txt'),
  await thirdPartyNotices(bundled.packages),
  { encoding: 'utf8', mode: 0o644 },
)
await writeFile(
  resolve(dist, 'THIRD_PARTY_COMPONENTS.cdx.json'),
  `${JSON.stringify(embeddedSbom(manifest, bundled.packages, bundled.lock), null, 2)}\n`,
  { encoding: 'utf8', mode: 0o644 },
)
