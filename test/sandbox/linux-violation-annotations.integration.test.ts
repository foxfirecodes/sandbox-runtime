import { afterEach, describe, expect, it } from 'bun:test'
import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'
import shellquote from 'shell-quote'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import type { SandboxRuntimeConfig } from '../../src/sandbox/sandbox-config.js'
import { whichSync } from '../../src/utils/which.js'
import { spawnAsync } from '../helpers/spawn.js'
import { isLinux } from '../helpers/platform.js'

const canRunLinuxSandbox =
  isLinux &&
  process.env.SANDBOX_RUNTIME !== '1' &&
  whichSync('strace') !== null &&
  whichSync('bwrap') !== null &&
  whichSync('socat') !== null

describe.if(canRunLinuxSandbox)(
  'Linux sandbox violation annotations (integration)',
  () => {
    afterEach(async () => {
      await SandboxManager.reset()
    })

    it('annotates a denied write when enableLogMonitor is true', async () => {
      const root = fs.mkdtempSync(path.join(os.tmpdir(), 'srt-annot-'))
      const blockedPath = path.join(root, 'blocked.txt')
      const config: SandboxRuntimeConfig = {
        network: {
          allowedDomains: [],
          deniedDomains: [],
        },
        filesystem: {
          denyRead: [],
          allowRead: [],
          allowWrite: [root],
          denyWrite: [blockedPath],
        },
      }

      await SandboxManager.initialize(config, undefined, true)
      const command = `printf nope > ${shellquote.quote([blockedPath])}`
      const wrapped = await SandboxManager.wrapWithSandbox(command)
      const result = await spawnAsync(wrapped, { timeout: 10_000 })
      SandboxManager.cleanupAfterCommand()

      const annotated = SandboxManager.annotateStderrWithSandboxFailures(
        command,
        result.stderr,
      )

      expect(result.status).not.toBe(0)
      expect(annotated).toContain('<sandbox_violations>')
      expect(annotated).toContain('linux file-write denied')
      expect(annotated).toContain(blockedPath)
    })
  },
)
