const NSTemporaryDirectory = new NativeFunction(Module.findExportByName(null, 'NSTemporaryDirectory'), 'pointer', [])


module.exports = {
  NSTemporaryDirectory,
}