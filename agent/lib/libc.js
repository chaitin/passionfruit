const open = new NativeFunction(Module.findExportByName(null, 'open'), 'int', ['pointer', 'int', 'int'])

module.exports = {
  open,
}

