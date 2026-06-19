import { spawnSync } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import * as fs from 'node:fs'
import * as path from 'node:path'
import type { SandboxViolationEvent } from './macos-sandbox-utils.js'
import type { IgnoreViolationsConfig } from './sandbox-config.js'
import { encodeSandboxedCommand } from './sandbox-utils.js'
import { logForDebugging } from '../utils/debug.js'
import { whichSync } from '../utils/which.js'

export interface LinuxViolationTraceSession {
  runId: string
  command: string
  encodedCommand: string
  traceDir: string
  tracePrefix: string
  parsed: boolean
}

export interface LinuxStraceConfig {
  stracePath: string
  args: string[]
}

export interface LinuxViolationTraceConfig {
  tracePrefix: string
  stracePath: string
  straceArgs: string[]
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
  }
}

export function parseLinuxViolationTraceSession(
  session: LinuxViolationTraceSession,
  ignoreViolations?: IgnoreViolationsConfig,
): SandboxViolationEvent[] {
  if (session.parsed) return []

  const events: SandboxViolationEvent[] = []
  const seen = new Set<string>()

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
      const eventLine = parseTraceLine(line.trim())
      if (!eventLine || seen.has(eventLine)) continue
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

function parseTraceLine(line: string): string | undefined {
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
    return formatNetworkFailure(syscall, args, errno, message, line)
  }

  if (FILE_SYSCALLS.has(syscall)) {
    return formatFileFailure(syscall, args, errno, message, line)
  }

  return `linux trace failure: ${line}`
}

function formatFileFailure(
  syscall: string,
  args: string,
  errno: string,
  message: string,
  raw: string,
): string {
  const filePath = extractFirstString(args)
  const op = inferFileOperation(syscall, args)
  if (!filePath) {
    return `linux file-${op} denied: ${syscall} -> ${errno} (${message}); raw=${raw}`
  }
  return `linux file-${op} denied: ${syscall}("${filePath}") -> ${errno} (${message})`
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
