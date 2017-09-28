/* 
 * common hook
 */

'use strict'

const subject = 'hook'

const hooked = {}
const swizzled = {}

const now = () => (new Date()).getTime()


function hook(lib, func, signature) {
  const funcPtr = Module.findExportByName(lib, func)
  if (!funcPtr)
    throw new Error('symbol not found')

  if (!lib) {
    let mod = Process.getModuleByAddress(funcPtr)
    lib = mod.name
  }

  if (hooked[lib] && hooked[lib][func])
    return true

  let intercept = Interceptor.attach(funcPtr, {
    onEnter(args) {
      let time = now()
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
        lib,
        func,
        backtrace,
        time,
      })
    },
    onLeave(retVal) {
      let time = now()

      send({
        subject,
        event: 'return',
        lib,
        func,
        time,
        backtrace: this.backtrace,
        ret: retVal,
      })
    },
  })

  if (!hooked[lib])
    hooked[lib] = { func: intercept }
  else
    hooked[lib][func] = intercept

  return true
}

function unhook(lib, func) {
  if (hooked[lib] && hooked[lib][func]) {
    Interceptor.revert(Module.findExportsByName(lib, func))
    delete hooked[lib][func]
    return true
  }

  throw new Error('function has not been hooked before')
}


function swizzle(clazz, sel) {
  if (swizzled[clazz] && swizzled[clazz][sel])
    return true

  if (!ObjC.classes.hasOwnProperty(clazz))
    throw new Error(`class ${clazz} not found`)

  if (!ObjC.classes[clazz].hasOwnProperty(sel))
    throw new Error(`method ${sel} not found in ${clazz}`)

  let method = ObjC.classes[clazz][sel]
  let original = method.implementation

  if (!swizzled[clazz])
    swizzled[clazz] = { sel: original }
  else
    swizzled[clazz][sel] = original

  method.implementation = ObjC.implement(method, function(self, selector, ...args) {
    let time = now()
    let readable = args.map((arg, index) => {
      if (method.argumentTypes[index] === 'pointer')
        return ObjC.Object(arg).toString()
      else
        return arg
    })

    send({
      subject,
      event: 'objc-call',
      args: readable,
      clazz,
      sel,
      backtrace,
      time,
    })

    let ret = original.apply(null, [self, selector, ...args])
    time = now()
    send({
      subject,
      event: 'objc-return',
      clazz,
      sel,
      ret,
      backtrace,
      time,
    })
    return ret
  })

}

function unswizzle(clazz, sel) {
  if (swizzled[clazz] && swizzled[clazz][sel]) {
    let method = ObjC.classes[clazz][sel]
    let original = swizzled[clazz][sel]

    method.implementation = original

    delete swizzled[clazz][sel]
    return true
  }

  throw new Error(`method ${sel} of ${clazz} has not been swizzled`)
}

module.exports = {
  hook,
  unhook,
  swizzle,
  unswizzle,
}