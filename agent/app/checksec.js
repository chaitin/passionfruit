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
  const main = Process.enumerateModulesSync()[0]
  const buffer = new ReadOnlyMemoryBuffer(main.base, main.size)
  const info = macho.parse(buffer)
  const imports = new Set(Module.enumerateImports(main.path).map(i => i.name))
  const result = {
    pie: Boolean(info.flags.pie),
    encrypted: info.cmds.some(cmd => /^encryption_info_(32|64)$/.test(cmd.type) && cmd.id === 1),
    canary: imports.has('__stack_chk_guard'),
    arc: imports.has('objc_release')
  }

  const hasCodeSign = info.cmds.filter(cmd => cmd.type === 'code_signature').length > 0
  if (!hasCodeSign)
    return result

  const CS_OPS_ENTITLEMENTS_BLOB = 7
  const csops = new NativeFunction(
    Module.findExportByName('libsystem_kernel.dylib', 'csops'),
    'int',
    ['int', 'int', 'pointer', 'uint64']
  )

  // struct csheader {
  //   uint32_t magic;
  //   uint32_t length;
  // };

  const SIZE_OF_CSHEADER = 8
  const csheader = Memory.alloc(SIZE_OF_CSHEADER)
  if (csops(Process.id, CS_OPS_ENTITLEMENTS_BLOB, csheader, SIZE_OF_CSHEADER) === -1) {
    const reader = new ReadOnlyMemoryBuffer(csheader, SIZE_OF_CSHEADER)
    const length = reader.readUInt32BE(4)
    const content = Memory.alloc(length)
    if (csops(Process.id, CS_OPS_ENTITLEMENTS_BLOB, content, length) === 0) {
      result.entitlements = dictFromPlistCharArray(
        content.add(SIZE_OF_CSHEADER), length - SIZE_OF_CSHEADER
      )
    }
  }

  return result
}
