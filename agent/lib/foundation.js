function NSTemporaryDirectory() {
  const func = new NativeFunction(Module.findExportByName(null, 'NSTemporaryDirectory'), 'pointer', [])
  const tmp = func()
  return tmp ? new ObjC.Object(tmp).toString() : null
}

module.exports = {
  NSTemporaryDirectory,
}