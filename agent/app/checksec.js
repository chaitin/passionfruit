/* eslint import/no-extraneous-dependencies: 0 */

import ReadOnlyMemoryBuffer from './lib/romembuffer'
import { parse } from './lib/macho'
import { dictFromPlistCharArray } from './lib/nsdict'
import { open, close, mmap, munmap, O_RDONLY, PROT_READ, MAP_PRIVATE } from './lib/libc'


const CSSLOT_ENTITLEMENTS = 5
const CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0


function parseEntitlements(data) {
  if (data.readUInt32BE(0) !== CSMAGIC_EMBEDDED_SIGNATURE)
    return null

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
  const info = parse(buffer)
  // todo: refactor me

  let entitlements = null
  for (const cmd of info.cmds) {
    // shoot, this command isn't mapped in memory for 3rd-party apps
    if (cmd.type === 'code_signature') {
      const fd = open(Memory.allocUtf8String(appModule.path), O_RDONLY, 0)
      const pageSize = ((cmd.dataoff + cmd.datasize) >> 12) << 12 // page size unit: 4096
      const addr = mmap(NULL, pageSize, PROT_READ, MAP_PRIVATE, fd, 0)
      const memBuffer = new ReadOnlyMemoryBuffer(addr.add(cmd.dataoff), cmd.datasize)
      entitlements = parseEntitlements(memBuffer)
      munmap(addr, pageSize)
      close(fd)
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
