const FLAG_ENCRYPTED = 0x1
const FLAG_PIE = 0x2
const FLAG_CANARY = 0x4
const FLAG_ARC = 0x8
const FLAG_RESTRICT = 0x10


module.exports = function() {
  return new Promise((resolve, reject) => {
    var result = {}

    // check flags
    var addr = Module.findExportByName('ipaspect.dylib', 'ipaspect_checksec');
    if (!addr)
      return reject('ipaspect agent has not been installed on device')

    var checksec = new NativeFunction(addr, 'int', []);
    var flags = checksec();
    if (flags & FLAG_PIE)
      result.pie = true

    if (flags & FLAG_ENCRYPTED)
      result.encrypted = true

    if (flags & FLAG_RESTRICT)
      result.restricted = true

    Process.enumerateModules({
      onMatch: function(module) {
        Module.enumerateImports(module.name, {
          onMatch: function(imp) {
            if (imp.name == '__stack_chk_guard')
              result.canary = true

            if (imp.name == 'objc_release')
              result.arc = true
          },
          onComplete: function() {
            resolve(result)
          }
        })
        // the first module is the main executable
        return 'stop'
      },
      onComplete: function() {}
    })
  })
}