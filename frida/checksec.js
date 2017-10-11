const FLAG_ENCRYPTED = 0x1
const FLAG_PIE = 0x2
const FLAG_RESTRICT = 0x10


module.exports = () => new Promise((resolve, reject) => {
  const result = {}

  // check flags
  const addr = Module.findExportByName('passionfruit.dylib', 'passionfruit_checksec')
  if (!addr) {
    reject(new Error('passionfruit agent has not been installed on device'))
    return
  }

  const checksec = new NativeFunction(addr, 'int', [])
  const flags = checksec()
  if (flags & FLAG_PIE)
    result.pie = true

  if (flags & FLAG_ENCRYPTED)
    result.encrypted = true

  if (flags & FLAG_RESTRICT)
    result.restricted = true

  Process.enumerateModules({
    onMatch(module) {
      Module.enumerateImports(module.name, {
        onMatch(imp) {
          if (imp.name === '__stack_chk_guard')
            result.canary = true

          if (imp.name === 'objc_release')
            result.arc = true
        },
        onComplete() {
          resolve(result)
        },
      })
      // the first module is the main executable
      return 'stop'
    },
    onComplete() {},
  })
})
