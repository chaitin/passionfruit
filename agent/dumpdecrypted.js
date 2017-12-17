import { open, close, read, write, lseek, mmap, munmap } from './lib/libc'

import macho from 'macho'

import { getDataAttrForPath } from './lib/foundation'
import uuidv4 from './lib/uuid'
import ReadOnlyMemoryBuffer from './lib/romembuffer'

const O_RDONLY = 0
const PROT_READ = 0x01
const MAP_PRIVATE = 0x0002

const MH_MAGIC = 0xFEEDFACE,
  MH_CIGAM = 0xCEFAEDFE,
  MH_MAGIC_64 = 0xFEEDFACF,
  MH_CIGAM_64 = 0xCFFAEDFE,
  FAT_MAGIC = 0xCAFEBABE,
  FAT_CIGAM = 0xBEBAFECA,
  FAT_MAGIC_64 = 0xCAFEBABF,
  FAT_CIGAM_64 = 0xBFBAFEC


function dump(name) {
  const module = Process.findModuleByName(name)
  if (module === null)
    throw new Error(`${name} is not a valid module name`)

  const session = uuidv4()
  const subject = 'download'
  const { size } = getDataAttrForPath(module.path)
  const fd = open(Memory.allocUtf8String(module.path), O_RDONLY, 0)
  if (fd == -1)
    throw new Error(`unable to read file ${module.path}, dump failed`)

  const buffer = new ReadOnlyMemoryBuffer(module.base, module.size)
  const headers = macho.parse(buffer)
  const mapped = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0)
  const magic = Memory.readU32(mapped)

  let fileOffset = 0
  if ([FAT_CIGAM, FAT_CIGAM_64, FAT_MAGIC, FAT_MAGIC_64].indexOf(magic) > -1) {
    const ncmds = Memory.readU32(mapped.add(4))
    for (let cmd = 0, cursor = 12; cmd < ncmds; cursor += 20, cmd++) {
      const cpu = Memory.readU32(mapped.add(cursor))
      const offset = Memory.readU32(mapped.add(cursor + 4))
      const cmdSize = Memory.readU32(mapped.add(cursor + 8))
      const align = Memory.readU32(mapped.add(cursor + 12))

      if (offset && cmdSize) {
        console.log(fileOffset, cpu, cmdSize, align)
        // todo: check cpuType
      }
    }
  } else if ([MH_MAGIC, MH_CIGAM, MH_MAGIC_64, MH_CIGAM_64].indexOf(magic) === -1) {
    throw new Error(`invalid magic: ${magic}`)
  }

  const matches = headers.cmds.filter(cmd => /^encryption_info_(32|64)$/.test(cmd.type) && cmd.id === 1)

  if (!matches.length)
    throw new Error(`Module ${name} is not encrypted`)

  const [encryptionInfo, ] = matches
  const stream = new UnixInputStream(fd, { autoClose: true })
  return

  const run = () => {
    // header to encryption_info


    return

    let buffer = Memory.readByteArray(module.base, encryptionInfo.fileoff)
    send({
      subject,
      event: 'data',
      session,
    }, buffer)

    // reset cryptid
    const [, bits] = /^encryption_info_(32|64)$/.exec(encryptionInfo.type)
    buffer = new ArrayBuffer(parseInt(bits, 10) === 64 ? 16 : 12)
    send({
      subject,
      event: 'data',
      session,
    }, buffer)

    // const offset = encryptionInfo.fileoff + 

  }

  send({
    subject,
    event: 'start',
    session,
  })

  setImmediate(run)
  return {
    size,
    session,
  }

  // const tmp = NSTemporaryDirectory() + module.name + '.decrypted'
  // const output = Memory.allocUtf8String(tmp)
  // let outfd = open(output, O_CREAT | O_RDWR, PERM)
  // if (outfd == -1) {
  //   outfd = open(output, O_RDWR, PERM)
  //   throw new Error(`unable to create writable file ${tmp}, please check your device`)
  // }

  // copy file
  // const SIZE = 1024 * 1024
  // const buffer = Memory.alloc(SIZE)
  // let n
  // while ((n = read(fd, buffer, SIZE)) > 0) {
  //   write(outfd, buffer, n)
  // }
  // close(fd)

  // decrypt
  /*
  let is64bit = false
  let sizeOfHeader = 0

  const { base } = module
  const magic = Memory.readU32(base)
  if (magic == MH_MAGIC || magic == MH_CIGAM) {
    is64bit = false
    sizeOfHeader = 28
  } else if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
    is64bit = true
    sizeOfHeader = 32
  } else {
    throw new Error('unknown file format')
  }

  const ncmds = Memory.readU32(base.add(16))
  let offset = sizeOfHeader
  let offsetCryptOff = -1
  let cryptOff = 0
  let cryptSize = 0

  for (let i = 0; i < ncmds; i++) {
    const cmd = Memory.readU32(base.add(offset))
    const cmdsize = Memory.readU32(base.add(offset + 4))
    if (cmd == LC_ENCRYPTION_INFO || cmd == LC_ENCRYPTION_INFO_64) {
      offsetCryptOff = offset + 8
      cryptOff = Memory.readU32(base.add(offsetCryptOff))
      cryptSize = Memory.readU32(base.add(offset + 12))
    }
    offset += cmdsize
  }

  if (offsetCryptOff != -1) {
    console.log('encrypted')
    console.log(offsetCryptOff.toString(16))
    console.log(cryptOff.toString(16))
    console.log(cryptSize.toString(16))

    // const buf = Memory.alloc(8)
    // Memory.writeU64(buf, 0)
    // lseek(outfd, offsetCryptOff, SEEK_SET)
    // write(outfd, buf, 8)
    // lseek(outfd, cryptOff, SEEK_SET)
    // write(outfd, base.add(cryptOff), cryptSize)
  }*/

  // close(outfd)
}

module.exports = dump