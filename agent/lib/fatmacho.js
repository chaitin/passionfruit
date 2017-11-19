const CAFEBABE = 3405691582;

const cpuType = {
  0x00000003: 'i386',
  0x80000003: 'x86_64',
  0x00000009: 'arm',
  0x80000009: 'arm64',
  0x00000000: 'arm64',
  0x0000000a: 'ppc_32',
  0x8000000a: 'ppc_64',
}

export function parse(data) {
  const u32 = x => data.readUInt32BE(x)
  const magic = u32(0)
  if (magic !== CAFEBABE)
    throw new Error('invalid fat macho')

  const ncmds = u32(4)
  const cmds = []
  for (let cmd = 0, cursor = 12; cmd < ncmds; cursor += 20, cmd++) {
    const cpu = u32(cursor)
    const offset = u32(cursor + 4)
    const size = u32(cursor + 8)
    const align = u32(cursor + 12)

    if (offset === 0 || size === 0)
      continue

    cmds.push({
      arch: cpuType[cpu] || 'N/A',
      cpu,
      offset,
      size,
      align
    })
  }

  return cmds
}