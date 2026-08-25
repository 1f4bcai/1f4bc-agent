import { randomUUID } from 'node:crypto'
import { constants, type Stats } from 'node:fs'
import {
  link,
  lstat,
  mkdir,
  open,
  rename,
  unlink,
} from 'node:fs/promises'
import { dirname, join } from 'node:path'

const LOCK_WAIT_MS = 10_000
const IS_UNIX = process.platform !== 'win32'

function errorCode(error: unknown): string | undefined {
  return (error as NodeJS.ErrnoException).code
}

function currentUserId(): number | undefined {
  if (!IS_UNIX) return undefined
  if (typeof process.geteuid === 'function') return process.geteuid()
  if (typeof process.getuid === 'function') return process.getuid()
  return undefined
}

function assertPrivateDirectory(info: Stats, path: string): void {
  if (info.isSymbolicLink() || !info.isDirectory()) {
    throw new Error(`local journal directory must be a real directory: ${path}`)
  }
  if (!IS_UNIX) return
  const uid = currentUserId()
  if (uid !== undefined && info.uid !== uid) {
    throw new Error(`local journal directory is not owned by the current user: ${path}`)
  }
}

function assertPrivateFile(info: Stats, label: string): void {
  if (info.isSymbolicLink() || !info.isFile() || info.nlink !== 1) {
    throw new Error(`${label} must be a single-link regular file`)
  }
  if (!IS_UNIX) return
  const uid = currentUserId()
  if (uid !== undefined && info.uid !== uid) {
    throw new Error(`${label} is not owned by the current user`)
  }
  if ((info.mode & 0o077) !== 0) throw new Error(`${label} has unsafe permissions`)
}

async function ensurePrivateDirectory(path: string): Promise<void> {
  await mkdir(path, { recursive: true, mode: 0o700 })
  const initial = await lstat(path)
  assertPrivateDirectory(initial, path)
  const flags = constants.O_RDONLY |
    (IS_UNIX ? constants.O_NOFOLLOW | (constants.O_DIRECTORY ?? 0) : 0)
  const handle = await open(path, flags)
  try {
    const opened = await handle.stat()
    assertPrivateDirectory(opened, path)
    if (opened.dev !== initial.dev || opened.ino !== initial.ino) {
      throw new Error(`local journal directory changed while it was opened: ${path}`)
    }
    if (IS_UNIX && (opened.mode & 0o077) !== 0) await handle.chmod(0o700)
  } finally {
    await handle.close()
  }
}

/** Read a bounded private file without following links or accepting inode swaps. */
export async function readPrivateFile(
  target: string,
  maxBytes: number,
  label = 'local journal',
): Promise<string> {
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) throw new Error('invalid read limit')
  await ensurePrivateDirectory(dirname(target))
  const initial = await lstat(target)
  assertPrivateFile(initial, label)
  if (initial.size > maxBytes) throw new Error(`${label} exceeds its byte-size safety limit`)

  const handle = await open(target, constants.O_RDONLY | (IS_UNIX ? constants.O_NOFOLLOW : 0))
  try {
    const opened = await handle.stat()
    if (
      !opened.isFile() ||
      opened.nlink !== 1 ||
      opened.dev !== initial.dev ||
      opened.ino !== initial.ino
    ) {
      throw new Error(`${label} changed while it was opened`)
    }
    const raw = await handle.readFile({ encoding: 'utf8' })
    if (Buffer.byteLength(raw, 'utf8') > maxBytes) {
      throw new Error(`${label} exceeds its byte-size safety limit`)
    }
    const final = await lstat(target)
    if (final.dev !== opened.dev || final.ino !== opened.ino || final.isSymbolicLink()) {
      throw new Error(`${label} changed while it was read`)
    }
    return raw
  } finally {
    await handle.close()
  }
}

async function delay(milliseconds: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, milliseconds))
}

/** Serialize short, local journal mutations across CLI processes. */
export async function withFileLock<T>(
  target: string,
  operation: () => Promise<T>,
  options: { waitMs?: number } = {},
): Promise<T> {
  const directory = dirname(target)
  await ensurePrivateDirectory(directory)
  const lockPath = `${target}.lock`
  const token = randomUUID()
  const startedAt = Date.now()
  const waitMs = options.waitMs ?? LOCK_WAIT_MS
  let handle

  while (!handle) {
    try {
      handle = await open(lockPath, 'wx', 0o600)
      await handle.writeFile(`${JSON.stringify({ pid: process.pid, token, createdAt: Date.now() })}\n`)
      await handle.sync()
    } catch (error) {
      if (errorCode(error) !== 'EEXIST') throw error
      if (Date.now() - startedAt >= waitMs) {
        throw new Error(
          `local journal is locked: ${target}; if no CLI process is running, remove ${lockPath} manually`,
        )
      }
      await delay(10)
    }
  }

  try {
    return await operation()
  } finally {
    await handle.close()
    try {
      const current = JSON.parse(await readPrivateFile(lockPath, 4_096, 'local journal lock')) as {
        token?: unknown
      }
      if (current.token === token) await unlink(lockPath)
    } catch (error) {
      if (errorCode(error) !== 'ENOENT') throw error
    }
  }
}

/** Replace a private journal only after its complete contents are on disk. */
export async function atomicWritePrivate(target: string, contents: string): Promise<void> {
  const directory = dirname(target)
  await ensurePrivateDirectory(directory)
  const temporary = join(directory, `.${process.pid}.${randomUUID()}.tmp`)
  const handle = await open(temporary, 'wx', 0o600)
  try {
    await handle.writeFile(contents, 'utf8')
    await handle.sync()
  } finally {
    await handle.close()
  }
  try {
    try {
      assertPrivateFile(await lstat(target), 'local journal')
    } catch (error) {
      if (errorCode(error) !== 'ENOENT') throw error
    }
    await rename(temporary, target)
    const directoryHandle = await open(directory, 'r')
    try {
      await directoryHandle.sync()
    } finally {
      await directoryHandle.close()
    }
  } catch (error) {
    await unlink(temporary).catch((unlinkError) => {
      if (errorCode(unlinkError) !== 'ENOENT') throw unlinkError
    })
    throw error
  }
}

/** Create an immutable private sidecar without ever replacing an existing path. */
export async function atomicCreatePrivate(target: string, contents: string): Promise<boolean> {
  const directory = dirname(target)
  await ensurePrivateDirectory(directory)
  const temporary = join(directory, `.${process.pid}.${randomUUID()}.tmp`)
  const handle = await open(temporary, 'wx', 0o600)
  try {
    await handle.writeFile(contents, 'utf8')
    await handle.sync()
  } finally {
    await handle.close()
  }

  let created = false
  try {
    try {
      await link(temporary, target)
      created = true
    } catch (error) {
      if (errorCode(error) !== 'EEXIST') throw error
    }
  } finally {
    await unlink(temporary).catch((error) => {
      if (errorCode(error) !== 'ENOENT') throw error
    })
  }
  if (created) {
    const directoryHandle = await open(directory, 'r')
    try {
      await directoryHandle.sync()
    } finally {
      await directoryHandle.close()
    }
  }
  return created
}
