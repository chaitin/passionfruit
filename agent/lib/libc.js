const wrap = (symbol, ret, args) => new NativeFunction(Module.findExportByName(null, symbol), ret, args)

const open = wrap('open', 'int', ['pointer', 'int', 'int'])
const close = wrap('close', 'int', ['int'])
const read = wrap('read', 'int', ['int', 'pointer', 'int'])
const write = wrap('write', 'int', ['int', 'pointer', 'int'])
const lseek = wrap('lseek', 'int64', ['int', 'int64', 'int'])
const mmap = wrap('mmap', 'pointer', ['pointer', 'uint', 'int', 'int', 'int', 'long'])
const munmap = wrap('munmap', 'int', ['pointer', 'uint'])


module.exports = {
  open,
  close,
  read,
  write,
  lseek,

  mmap,
  munmap,
}
