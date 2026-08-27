import { spawnSync } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import * as fs from 'node:fs'
import * as path from 'node:path'
import type { SandboxViolationEvent } from './macos-sandbox-utils.js'
import type { IgnoreViolationsConfig } from './sandbox-config.js'
import { encodeSandboxedCommand } from './sandbox-utils.js'
import { logForDebugging } from '../utils/debug.js'
import { whichSync } from '../utils/which.js'

export type LinuxReadMaskKind = 'tmpfs' | 'dev-null'
export type LinuxReadonlyBindReason =
  | 'denyWrite'
  | 'mandatoryDenyWrite'
  | 'symlinkDenyWrite'

export interface LinuxSandboxMountPlan {
  rootReadonly: boolean
  writableBinds: string[]
  readMasks: Array<{ path: string; kind: LinuxReadMaskKind }>
  readAllowBinds: string[]
  readonlyBinds: Array<{ path: string; reason: LinuxReadonlyBindReason }>
}

export interface LinuxViolationTracePolicy {
  filesystem: LinuxSandboxMountPlan
  networkRestricted: boolean
  unixSocketBlocking: boolean
}

export interface LinuxViolationTraceSession {
  runId: string
  command: string
  encodedCommand: string
  cwd: string
  traceDir: string
  tracePrefix: string
  parsed: boolean
  policy?: LinuxViolationTracePolicy
}

export interface LinuxStraceConfig {
  stracePath: string
  args: string[]
}

export interface LinuxViolationTraceConfig {
  tracePrefix: string
  stracePath: string
  straceArgs: string[]
  onPolicy?(policy: LinuxViolationTracePolicy): void
}

const FILE_SYSCALLS = new Set([
  'access',
  'chmod',
  'chown',
  'creat',
  'faccessat',
  'faccessat2',
  'fchmodat',
  'fchownat',
  'link',
  'linkat',
  'lstat',
  'mkdir',
  'mkdirat',
  'newfstatat',
  'open',
  'openat',
  'openat2',
  'readlink',
  'readlinkat',
  'rename',
  'renameat',
  'renameat2',
  'rmdir',
  'stat',
  'statx',
  'symlink',
  'symlinkat',
  'truncate',
  'unlink',
  'unlinkat',
  'utimensat',
])

const WRITE_SYSCALLS = new Set([
  'chmod',
  'chown',
  'creat',
  'fchmodat',
  'fchownat',
  'link',
  'linkat',
  'mkdir',
  'mkdirat',
  'rename',
  'renameat',
  'renameat2',
  'rmdir',
  'symlink',
  'symlinkat',
  'truncate',
  'unlink',
  'unlinkat',
  'utimensat',
])

const NETWORK_SYSCALLS = new Set([
  'accept',
  'accept4',
  'bind',
  'connect',
  'listen',
  'recvfrom',
  'recvmsg',
  'sendmsg',
  'sendto',
  'socket',
  'socketpair',
])

/**
 * Check that optimized Linux tracing is available. We intentionally require
 * status=failed support so enabling monitoring never silently dumps full traces.
 */
export function getLinuxStraceConfig(): LinuxStraceConfig {
  const stracePath = whichSync('strace')
  if (!stracePath) {
    throw new Error(
      'Linux sandbox violation monitoring requires strace, but strace was not found in PATH',
    )
  }

  const statusProbe = spawnSync(
    stracePath,
    ['-qq', '-e', 'trace=none', '-e', 'status=failed', 'true'],
    { encoding: 'utf8', timeout: 5000 },
  )
  if (statusProbe.status !== 0) {
    throw new Error(
      'Linux sandbox violation monitoring requires strace support for -e status=failed',
    )
  }

  const supportsSeccompBpf =
    spawnSync(
      stracePath,
      [
        '--seccomp-bpf',
        '-qq',
        '-e',
        'trace=none',
        '-e',
        'status=failed',
        'true',
      ],
      { encoding: 'utf8', timeout: 5000 },
    ).status === 0

  const args = [
    '-ff',
    '-qq',
    ...(supportsSeccompBpf ? ['--seccomp-bpf'] : []),
    '-e',
    'trace=%file,%network',
    '-e',
    'status=failed',
    '-e',
    'signal=none',
    '-s',
    '256',
  ]

  return { stracePath, args }
}

export function createLinuxViolationTraceSession(
  command: string,
): LinuxViolationTraceSession {
  const baseTmpDir =
    process.env.CLAUDE_CODE_TMPDIR || process.env.CLAUDE_TMPDIR || '/tmp/claude'
  fs.mkdirSync(baseTmpDir, { recursive: true })
  const traceRoot = path.join(baseTmpDir, 'srt-traces')
  fs.mkdirSync(traceRoot, { recursive: true })

  const runId = randomBytes(8).toString('hex')
  const traceDir = path.join(traceRoot, runId)
  fs.mkdirSync(traceDir, { recursive: true, mode: 0o700 })

  return {
    runId,
    command,
    encodedCommand: encodeSandboxedCommand(command),
    cwd: process.cwd(),
    traceDir,
    tracePrefix: path.join(traceDir, 'trace'),
    parsed: false,
  }
}

export function toLinuxViolationTraceConfig(
  session: LinuxViolationTraceSession,
  straceConfig: LinuxStraceConfig,
): LinuxViolationTraceConfig {
  return {
    tracePrefix: session.tracePrefix,
    stracePath: straceConfig.stracePath,
    straceArgs: [...straceConfig.args],
    onPolicy: policy => {
      session.policy = policy
    },
  }
}

export function parseLinuxViolationTraceSession(
  session: LinuxViolationTraceSession,
  ignoreViolations?: IgnoreViolationsConfig,
): SandboxViolationEvent[] {
  if (session.parsed) return []

  const events: SandboxViolationEvent[] = []
  const seen = new Set<string>()
  let suppressedCount = 0

  for (const file of getTraceFiles(session)) {
    let content: string
    try {
      content = fs.readFileSync(file, 'utf8')
    } catch (error) {
      logForDebugging(
        `[Linux violation tracer] Failed to read trace file ${file}: ${error}`,
        { level: 'error' },
      )
      continue
    }

    for (const line of content.split('\n')) {
      const trimmed = line.trim()
      const eventLine = parseTraceLine(trimmed, session)
      if (!eventLine) {
        if (trimmed) suppressedCount++
        continue
      }
      if (seen.has(eventLine)) continue
      if (
        shouldIgnoreLinuxViolation(eventLine, session.command, ignoreViolations)
      ) {
        continue
      }
      seen.add(eventLine)
      events.push({
        line: eventLine,
        command: session.command,
        encodedCommand: session.encodedCommand,
        timestamp: new Date(),
      })
    }
  }

  if (suppressedCount > 0 && process.env.SRT_DEBUG) {
    logForDebugging(
      `[Linux violation tracer] Suppressed ${suppressedCount} non-sandbox trace failures for command: ${session.command}`,
    )
  }

  session.parsed = true

  if (!process.env.SRT_DEBUG) {
    try {
      fs.rmSync(session.traceDir, { recursive: true, force: true })
    } catch (error) {
      logForDebugging(
        `[Linux violation tracer] Failed to remove trace dir ${session.traceDir}: ${error}`,
        { level: 'warn' },
      )
    }
  }

  return events
}

export function shouldIgnoreLinuxViolation(
  violationLine: string,
  command: string | undefined,
  ignoreViolations?: IgnoreViolationsConfig,
): boolean {
  if (!ignoreViolations) return false

  const wildcardPaths = ignoreViolations['*'] || []
  if (wildcardPaths.some(path => violationLine.includes(path))) {
    return true
  }

  if (!command) return false

  for (const [pattern, paths] of Object.entries(ignoreViolations)) {
    if (pattern === '*') continue
    if (!command.includes(pattern)) continue
    if (paths.some(path => violationLine.includes(path))) {
      return true
    }
  }

  return false
}

function getTraceFiles(session: LinuxViolationTraceSession): string[] {
  try {
    return fs
      .readdirSync(session.traceDir)
      .filter(file => file === 'trace' || /^trace(?:\.\d+)?$/.test(file))
      .map(file => path.join(session.traceDir, file))
      .sort()
  } catch {
    return []
  }
}

function parseTraceLine(
  line: string,
  session: LinuxViolationTraceSession,
): string | undefined {
  if (!line) return undefined

  // strace failed syscall lines look like:
  // openat(AT_FDCWD, "/path", O_RDONLY) = -1 EACCES (Permission denied)
  const match =
    /^(?:\[pid\s+\d+\]\s+)?([a-zA-Z0-9_]+)\((.*)\)\s+=\s+-1\s+([A-Z0-9_]+)\s+\(([^)]*)\)/.exec(
      line,
    )
  if (!match) return undefined

  const [, syscall, args, errno, message] = match
  if (!syscall || !args || !errno || !message) return undefined

  if (NETWORK_SYSCALLS.has(syscall)) {
    return shouldReportNetworkFailure(syscall, args, errno, session.policy)
      ? formatNetworkFailure(syscall, args, errno, message, line)
      : undefined
  }

  if (FILE_SYSCALLS.has(syscall)) {
    const filePath = extractFirstString(args)
    const normalizedPath = normalizeTracePath(filePath, session.cwd)
    const op = inferFileOperation(syscall, args)
    return shouldReportFileFailure(
      errno,
      op,
      normalizedPath,
      session.policy?.filesystem,
    )
      ? formatFileFailure(syscall, errno, message, line, filePath, op)
      : undefined
  }

  return `linux trace failure: ${line}`
}

function formatFileFailure(
  syscall: string,
  errno: string,
  message: string,
  raw: string,
  filePath: string | undefined,
  op: 'read' | 'write',
): string {
  if (!filePath) {
    return `linux file-${op} denied: ${syscall} -> ${errno} (${message}); raw=${raw}`
  }
  return `linux file-${op} denied: ${syscall}("${filePath}") -> ${errno} (${message})`
}

function shouldReportFileFailure(
  errno: string,
  op: 'read' | 'write',
  normalizedPath: string | undefined,
  mountPlan: LinuxSandboxMountPlan | undefined,
): boolean {
  if (!normalizedPath || !mountPlan) {
    return isStrongFileErrno(errno)
  }

  const activeReadMask = isUnderActiveReadMask(normalizedPath, mountPlan)
  const readonlyBind = isUnderReadonlyBind(normalizedPath, mountPlan)
  const outsideWritableRoot =
    mountPlan.rootReadonly &&
    !isUnderAny(normalizedPath, mountPlan.writableBinds)

  if (op === 'write') {
    if (readonlyBind || activeReadMask) return isWriteSandboxErrno(errno)
    if (outsideWritableRoot) return isWriteSandboxErrno(errno)
    return false
  }

  if (activeReadMask) {
    // denyRead tmpfs/dev-null masks can surface as ENOENT (hidden subtree),
    // EACCES/EPERM, or EINVAL for readlink against a dev-null file mask.
    return ['ENOENT', 'EACCES', 'EPERM', 'EINVAL'].includes(errno)
  }

  // Reads outside our actual read masks are normal application/host failures,
  // not sandbox denials. In particular, readlink regular-file => EINVAL and
  // optional config discovery => ENOENT are expected probing patterns.
  return false
}

function shouldReportNetworkFailure(
  syscall: string,
  args: string,
  errno: string,
  policy: LinuxViolationTracePolicy | undefined,
): boolean {
  if (syscall === 'socket' || syscall === 'socketpair') {
    const family = /\bAF_[A-Z0-9_]+\b/.exec(args)?.[0]
    return (
      family === 'AF_UNIX' && errno === 'EPERM' && !!policy?.unixSocketBlocking
    )
  }

  if (!policy?.networkRestricted) return false
  return ['ENETUNREACH', 'EHOSTUNREACH', 'EPERM', 'EACCES'].includes(errno)
}

function isStrongFileErrno(errno: string): boolean {
  return ['EACCES', 'EPERM', 'EROFS'].includes(errno)
}

function isWriteSandboxErrno(errno: string): boolean {
  return ['EACCES', 'EPERM', 'EROFS', 'ENOSPC'].includes(errno)
}

function inferFileOperation(syscall: string, args: string): 'read' | 'write' {
  if (WRITE_SYSCALLS.has(syscall)) return 'write'
  if (/\b(O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND)\b/.test(args))
    return 'write'
  if (/\bW_OK\b/.test(args)) return 'write'
  return 'read'
}

function formatNetworkFailure(
  syscall: string,
  args: string,
  errno: string,
  message: string,
  raw: string,
): string {
  if (syscall === 'socket' || syscall === 'socketpair') {
    const family = /\bAF_[A-Z0-9_]+\b/.exec(args)?.[0]
    const label = family === 'AF_UNIX' ? 'unix-socket' : 'network'
    return `linux ${label} denied: ${syscall}(${family ?? 'unknown-family'}) -> ${errno} (${message})`
  }

  const endpoint = extractEndpoint(args)
  if (endpoint) {
    return `linux network denied: ${syscall}(${endpoint}) -> ${errno} (${message})`
  }
  return `linux network denied: ${syscall} -> ${errno} (${message}); raw=${raw}`
}

function isUnderActiveReadMask(
  normalizedPath: string,
  mountPlan: LinuxSandboxMountPlan,
): boolean {
  for (const mask of mountPlan.readMasks) {
    if (mask.kind === 'dev-null') {
      if (normalizedPath === mask.path) return true
      continue
    }

    if (!isPathAtOrUnder(normalizedPath, mask.path)) continue
    if (isUnderAny(normalizedPath, mountPlan.readAllowBinds)) continue
    if (isUnderAny(normalizedPath, mountPlan.writableBinds)) continue
    return true
  }

  return false
}

function isUnderReadonlyBind(
  normalizedPath: string,
  mountPlan: LinuxSandboxMountPlan,
): boolean {
  return mountPlan.readonlyBinds.some(bind =>
    isPathAtOrUnder(normalizedPath, bind.path),
  )
}

function isUnderAny(normalizedPath: string, bases: string[]): boolean {
  return bases.some(base => isPathAtOrUnder(normalizedPath, base))
}

function isPathAtOrUnder(normalizedPath: string, basePath: string): boolean {
  if (basePath === '/') return normalizedPath.startsWith('/')
  return (
    normalizedPath === basePath || normalizedPath.startsWith(basePath + '/')
  )
}

function normalizeTracePath(
  tracePath: string | undefined,
  cwd: string,
): string | undefined {
  if (!tracePath) return undefined
  if (tracePath.startsWith('/')) return path.normalize(tracePath)
  return path.resolve(cwd, tracePath)
}

function extractEndpoint(args: string): string | undefined {
  const ip = /inet_addr\("([^"]+)"\)/.exec(args)?.[1]
  const port = /sin_port=htons\((\d+)\)/.exec(args)?.[1]
  if (ip && port) return `${ip}:${port}`

  const ipv6 = /inet_pton\(AF_INET6, "([^"]+)"/.exec(args)?.[1]
  const port6 = /sin6_port=htons\((\d+)\)/.exec(args)?.[1]
  if (ipv6 && port6) return `[${ipv6}]:${port6}`

  const unix = /sun_path="([^"]+)"/.exec(args)?.[1]
  if (unix) return `unix:${unix}`

  return undefined
}

function extractFirstString(args: string): string | undefined {
  const matches = [...args.matchAll(/"((?:\\.|[^"\\])*)"/g)]
  for (const match of matches) {
    const value = unescapeStraceString(match[1] ?? '')
    if (
      value.startsWith('/') ||
      value.startsWith('.') ||
      value.startsWith('~')
    ) {
      return value
    }
  }
  return matches[0]?.[1] ? unescapeStraceString(matches[0][1]) : undefined
}

function unescapeStraceString(value: string): string {
  try {
    return JSON.parse(`"${value.replace(/"/g, '\\"')}"`) as string
  } catch {
    return value.replace(/\\"/g, '"').replace(/\\\\/g, '\\')
  }
}
