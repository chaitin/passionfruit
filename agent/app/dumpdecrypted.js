import { open, close, write, lseek } from './lib/libc'
import { NSTemporaryDirectory } from './lib/foundation'
import { parse } from './lib/macho'

import ReadOnlyMemoryBuffer from './lib/romembuffer'

const O_RDONLY = 0
const O_RDWR = 2

const SEEK_SET = 0


function dump(name) {
  const module = Process.findModuleByName(name)
  if (module === null)
    throw new Error(`${name} is not a valid module name`)

  const buffer = new ReadOnlyMemoryBuffer(module.base, module.size)
  const info = parse(buffer)
  const matches = info.cmds.filter(cmd => /^encryption_info(_64)?$/.test(cmd.type) && cmd.id === 1)
  if (!matches.length)
    throw new Error(`Module ${name} is not encrypted`)

  const encryptionInfo = matches.pop()
  const fd = open(Memory.allocUtf8String(module.path), O_RDONLY, 0)

  if (fd === -1)
    throw new Error(`unable to read file ${module.path}, dump failed`)

  const tmp = [NSTemporaryDirectory(), module.name, '.decrypted'].join('')
  const output = Memory.allocUtf8String(tmp)

  // copy encrypted
  const err = Memory.alloc(Process.pointerSize)
  const fileManager = ObjC.classes.NSFileManager.defaultManager()
  if (fileManager.fileExistsAtPath_(tmp))
    fileManager.removeItemAtPath_error_(tmp, err)
  fileManager.copyItemAtPath_toPath_error_(module.path, tmp, err)
  const desc = Memory.readPointer(err)
  if (!desc.isNull())
    throw new Error(`failed to copy file: ${new ObjC.Object(desc).toString()}`)

  const outfd = open(output, O_RDWR, 0)

  // dump decrypted
  lseek(outfd, encryptionInfo.offset, SEEK_SET)
  write(outfd, module.base.add(encryptionInfo.offset), encryptionInfo.size)

  /*
    https://developer.apple.com/documentation/kernel/encryption_info_command
    https://developer.apple.com/documentation/kernel/encryption_info_command_64
  */

  // erase cryptoff, cryptsize and cryptid
  const zeros = Memory.alloc(12)
  lseek(outfd, encryptionInfo.fileoff + 8, SEEK_SET) // skip cmd and cmdsize
  write(outfd, zeros, 12)
  close(outfd)

  return tmp
}

module.exports = dump
