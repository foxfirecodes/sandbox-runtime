import { describe, expect, it } from 'bun:test'
import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'
import {
  parseLinuxViolationTraceSession,
  type LinuxSandboxMountPlan,
  type LinuxViolationTraceSession,
} from '../../src/sandbox/linux-violation-tracer.js'
import { encodeSandboxedCommand } from '../../src/sandbox/sandbox-utils.js'

const defaultMountPlan: LinuxSandboxMountPlan = {
  rootReadonly: true,
  writableBinds: ['/repo'],
  readMasks: [
    { path: '/home/user/.ssh', kind: 'tmpfs' },
    { path: '/ignored', kind: 'tmpfs' },
    { path: '/reported', kind: 'dev-null' },
  ],
  readAllowBinds: [],
  readonlyBinds: [{ path: '/repo/.env', reason: 'denyWrite' }],
}

function makeSession(command = 'node script.js'): LinuxViolationTraceSession {
  const traceDir = fs.mkdtempSync(path.join(os.tmpdir(), 'srt-trace-test-'))
  return {
    runId: 'run123',
    command,
    encodedCommand: encodeSandboxedCommand(command),
    cwd: process.cwd(),
    policy: {
      filesystem: defaultMountPlan,
      networkRestricted: true,
      unixSocketBlocking: true,
    },
    traceDir,
    tracePrefix: path.join(traceDir, 'trace'),
    parsed: false,
  }
}

describe('linux violation trace parser', () => {
  it('parses failed file, network, and unix socket syscalls into violations', () => {
    const command = 'node script.js'
    const session = makeSession(command)

    fs.writeFileSync(
      path.join(session.traceDir, 'trace.123'),
      [
        'openat(AT_FDCWD, "/home/user/.ssh/config", O_RDONLY|O_CLOEXEC) = -1 EACCES (Permission denied)',
        'openat(AT_FDCWD, "/repo/.env", O_WRONLY|O_CREAT|O_TRUNC, 0666) = -1 EROFS (Read-only file system)',
        'connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.2.3.4")}, 16) = -1 ENETUNREACH (Network is unreachable)',
        'socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0) = -1 EPERM (Operation not permitted)',
      ].join('\n'),
    )

    const events = parseLinuxViolationTraceSession(session)

    expect(events.map(e => e.line)).toEqual([
      'linux file-read denied: openat("/home/user/.ssh/config") -> EACCES (Permission denied)',
      'linux file-write denied: openat("/repo/.env") -> EROFS (Read-only file system)',
      'linux network denied: connect(1.2.3.4:443) -> ENETUNREACH (Network is unreachable)',
      'linux unix-socket denied: socket(AF_UNIX) -> EPERM (Operation not permitted)',
    ])
    expect(events.every(e => e.command === command)).toBe(true)
    expect(events.every(e => e.encodedCommand === session.encodedCommand)).toBe(
      true,
    )
  })

  it('suppresses benign readlink EINVAL outside actual read masks', () => {
    const session = makeSession()

    fs.writeFileSync(
      path.join(session.traceDir, 'trace.123'),
      'readlink(".git/index", 0x7fff, 1023) = -1 EINVAL (Invalid argument)',
    )

    expect(parseLinuxViolationTraceSession(session)).toEqual([])
  })

  it('reports readlink EINVAL when an actual dev-null read mask hides the target', () => {
    const session = makeSession()

    fs.writeFileSync(
      path.join(session.traceDir, 'trace.123'),
      'readlink("/reported", 0x7fff, 1023) = -1 EINVAL (Invalid argument)',
    )

    expect(parseLinuxViolationTraceSession(session).map(e => e.line)).toEqual([
      'linux file-read denied: readlink("/reported") -> EINVAL (Invalid argument)',
    ])
  })

  it('applies wildcard and command-specific ignoreViolations filters', () => {
    const command = 'npm test'
    const session = makeSession(command)

    fs.writeFileSync(
      path.join(session.traceDir, 'trace.123'),
      [
        'openat(AT_FDCWD, "/ignored/global", O_RDONLY|O_CLOEXEC) = -1 EACCES (Permission denied)',
        'openat(AT_FDCWD, "/ignored/npm", O_RDONLY|O_CLOEXEC) = -1 EACCES (Permission denied)',
        'openat(AT_FDCWD, "/reported", O_RDONLY|O_CLOEXEC) = -1 EACCES (Permission denied)',
      ].join('\n'),
    )

    const events = parseLinuxViolationTraceSession(session, {
      '*': ['/ignored/global'],
      npm: ['/ignored/npm'],
      git: ['/reported'],
    })

    expect(events.map(e => e.line)).toEqual([
      'linux file-read denied: openat("/reported") -> EACCES (Permission denied)',
    ])
  })
})
