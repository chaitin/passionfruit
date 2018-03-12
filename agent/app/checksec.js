/* eslint import/no-extraneous-dependencies: 0 */

import macho from 'macho'
// I doubt that if there will be fat macho on real device
import fatmacho from 'fatmacho'

import ReadOnlyMemoryBuffer from './lib/romembuffer'


const CSSLOT_ENTITLEMENTS = 5


function parseEntitlements(data) {
  const count = data.readUInt32BE(8)
  for (let i = 0; i < count; i++) {
    const base = 8 * i
    const type = data.readUInt32BE(base + 12)
    const blob = data.readUInt32BE(base + 16)
    if (type === CSSLOT_ENTITLEMENTS) {
      const size = data.readUInt32BE(blob + 4)
      const buf = data.slice(blob + 8, blob + size)
      return Memory.readUtf8String(buf.base, buf.length)
    }
  }
  return null
}

export default function checksec() {
  const appModule = Process.enumerateModulesSync()[0]
  const buffer = new ReadOnlyMemoryBuffer(appModule.base, appModule.size)

  let info = null
  try {
    const bins = fatmacho.parse(buffer)
    info = macho.parse(bins[0].data)
  } catch (e) {
    info = macho.parse(buffer)
  }

  let entitlements = null
  for (const cmd of info.cmds)
    if (cmd.type === 'code_signature')
      entitlements = parseEntitlements(buffer.slice(cmd.dataoff, cmd.datasize))

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
