/* 
 * common hook
 */

'use strict'

const subject = 'hook'


function hook(lib, func, signature) {
  const funcPtr = Module.findExportByName(lib, func)
  if (!lib) {
    let mod = Process.getModuleByAddress(funcPtr)
    lib = mod.name
  }
  let symbol = lib + '!' + func

  Interceptor.attach(funcPtr, {
    onEnter(args) {
      let readable = []
      for (let i = 0; i < signature.args.length; i++) {
        let arg = ptr(args[i])
        readable[i] = signature.args[i] === 'char *' ? Memory.readUtf8String(arg) : arg;
      }

      let backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress)

      this.backtrace = backtrace

      send({
        subject,
        event: 'call',
        args: readable,
        symbol,
        backtrace,
      })
    },
    onLeave(retVal) {
      send({
        subject,
        event: 'return',
        symbol,
        backtrace: this.backtrace,
        ret: retVal,
      })
    },
  })

  return true
}

module.exports = () => {
  hook('/usr/lib/libSystem.B.dylib', 'open', { args: ['char *', 'int'], ret: 'int'})
}