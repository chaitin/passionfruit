/* eslint import/no-extraneous-dependencies: 0 */

import macho from 'macho'
import ReadOnlyMemoryBuffer from './lib/romembuffer'
import { dictFromPlistCharArray } from './lib/nsdict'


const CSSLOT_ENTITLEMENTS = 5
const CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0


function parseEntitlements(data) {
  const count = data.readUInt32BE(8)
  if (count > 16)
    throw new Error(`invalid count ${count.toString(16)}`)

  for (let i = 0; i < count; i++) {
    const base = 8 * i
    const type = data.readUInt32BE(base + 12)
    const blob = data.readUInt32BE(base + 16)
    if (type === CSSLOT_ENTITLEMENTS) {
      const size = data.readUInt32BE(blob + 4)
      const buf = data.slice(blob + 8, blob + size)
      return dictFromPlistCharArray(buf.base, buf.length)
    }
  }
  return null
}

export default function checksec() {
  const appModule = Process.enumerateModulesSync()[0]
  const buffer = new ReadOnlyMemoryBuffer(appModule.base, appModule.size)
  const info = macho.parse(buffer)

  let entitlements = null

  for (const cmd of info.cmds) {
    if (cmd.type === 'code_signature') {
      /* eslint no-loop-func: 0 */

      let executableOffset = 0
      Process.enumerateRanges('r', {
        onMatch(range) {
          if (!range.file || range.file.path.indexOf(appModule.path) === -1)
            return ''

          if (range.protection === 'r-x') {
            executableOffset = range.file.offset
            return ''
          }

          if (range.protection !== 'r--')
            return ''

          const cmdPtr = range.base.sub(range.file.offset - executableOffset).add(cmd.dataoff)
          const buf = new ReadOnlyMemoryBuffer(cmdPtr, cmd.datasize)
          if (buf.readUInt32BE(0) === CSMAGIC_EMBEDDED_SIGNATURE) {
            entitlements = parseEntitlements(buf)
            return 'stop'
          }

          return ''
        },
        onComplete() {},
      })

      break
    }
  }

  const importNames = Module.enumerateImportsSync(appModule.path).reduce((names, imp) => {
    names.add(imp.name)
    return names
  }, new Set())

  return {
    entitlements,
    pie: Boolean(info.flags.pie),
    encrypted: info.cmds.some(cmd => /^encryption_info_(32|64)$/.test(cmd.type) && cmd.id === 1),
    canary: importNames.has('__stack_chk_guard'),
    arc: importNames.has('objc_release'),
  }
}
