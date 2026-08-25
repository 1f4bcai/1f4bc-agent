import { rm } from 'node:fs/promises'
import { basename, dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const dist = resolve(packageRoot, 'dist')

if (basename(dist) !== 'dist' || dirname(dist) !== packageRoot) {
  throw new Error(`refusing to clean unexpected path: ${dist}`)
}

await rm(dist, { recursive: true, force: true })
