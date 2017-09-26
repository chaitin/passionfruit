'use strict'

let ptr = Module.findExportByName(null, 'open')
if (!ptr)
  throw new Error('unable to resolve syscalls')

const open = new NativeFunction(ptr, 'int', ['pointer', 'int', 'int'])

module.exports = {
  open,
}

