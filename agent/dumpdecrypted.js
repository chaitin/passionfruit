import { open, close, read, write, lseek } from './lib/libc'
import { NSTemporaryDirectory } from './lib/foundation'

const { NSString, NSFileManager } = ObjC.classes


const O_RDONLY = 0
const O_WRONLY = 1
const O_RDWR = 2
const O_CREAT = 512

const SEEK_SET = 0
const SEEK_CUR = 1
const SEEK_END = 2


// todo: wrap macho related functions to a module
const MH_MAGIC = 0xfeedface
const MH_CIGAM = 0xcefaedfe
const MH_MAGIC_64 = 0xfeedfacf
const MH_CIGAM_64 = 0xcffaedfe
const LC_SEGMENT = 0x1
const LC_SEGMENT_64 = 0x19
const LC_ENCRYPTION_INFO = 0x21
const LC_ENCRYPTION_INFO_64 = 0x2C


function dump(name) {
  const module = Module.findBaseAddress(name)
  if (module === null)
    throw new Error(`${module} is not a valid module name`)

  const fd = open(Memory.allocUtf8String(module.path), O_RDONLY, 0)
  if (fd == -1)
    throw new Error(`unable to read file ${module.path}, dump failed`)

  const tmp = NSTemporaryDirectory() + '/' + module.name + '.decrypted'
  const outfd = open(Memory.allocUtf8String(tmp), O_CREAT | O_RDWR, 0)
  if (outfd == -1)
    throw new Error(`unable to create writable file ${tmp}, please check your device`)

  // copy file
  const SIZE = 1024 * 1024
  const buffer = Memory.alloc(SIZE)
  while ((n = read(fd, buffer, SIZE)) > 0) {
    write(outfd, buffer, n)
  }
  close(fd)

  // decrypt
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
    const cmdSize = Memory.readU32(base.add(offset + 4))
    if (cmd == LC_ENCRYPTION_INFO || cmd == LC_ENCRYPTION_INFO_64) {
      offsetCryptOff = offset + 8
      cryptOff = Memory.readU32(base.add(offsetCryptOff))
      cryptSize = Memory.readU32(base.add(offset + 12))
    }
    offset += cmdsize
  }

  if (offsetCryptOff != -1) {
    const buf = Memory.alloc(8)
    Memory.writeU64(buf, 0)
    lseek(outfd, offsetCryptOff, SEEK_SET)
    write(outfd, tpbuf, 8)
    lseek(otufd, cryptOff, SEEK_SET)
    write(outfd, base.add(cryptOff), cryptSize)
  }

  close(outfd)
}

module.exports = dump