/* 
 * common hook
 */

'use strict'

require('./cccrypt')

const subject = 'hook'

const hooked = {}
const swizzled = {}

const now = () => (new Date()).getTime()
const readable = (type, arg) => type === 'char *' ? Memory.readUtf8String(arg) : arg


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
      let pretty = []
      for (let i = 0; i < signature.args.length; i++) {
        let arg = ptr(args[i])
        pretty[i] = readable(signature.args[i], arg)
      }

      let backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress).filter(e => e.name)

      this.backtrace = backtrace

      send({
        subject,
        event: 'call',
        args: pretty,
        lib,
        func,
        backtrace,
        time,
      })
    },
    onLeave(retVal) {
      if (!signature.ret)
        return

      let time = now()
      let ret = readable(signature.ret, retVal)

      send({
        subject,
        event: 'return',
        lib,
        func,
        time,
        backtrace: this.backtrace,
        ret,
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


function swizzle(clazz, sel, traceResult) {
  if (swizzled[clazz] && swizzled[clazz][sel])
    return true

  if (!ObjC.classes.hasOwnProperty(clazz))
    throw new Error(`class ${clazz} not found`)

  if (!ObjC.classes[clazz].hasOwnProperty(sel))
    throw new Error(`method ${sel} not found in ${clazz}`)

  let method = ObjC.classes[clazz][sel]
  if (!swizzled[clazz])
    swizzled[clazz] = { sel: true }
  else
    swizzled[clazz][sel] = true

  traceResult = typeof traceResult === 'undefined' ? true : Boolean(traceResult)

  let onLeave
  if (traceResult) {
    onLeave = function(retVal) {
      let time = now()
      let { backtrace } = this
      let ret = retVal
      try {
        ret = new ObjC.Object(ret).toString()
      } catch (_) {}
      send({
        subject,
        event: 'objc-return',
        clazz,
        sel,
        ret,
        time,
      })
    }
  }

  Interceptor.attach(method.implementation, {
    onEnter(args) {
      let time = now()
      let readable = []
      for (let i = 2; i < method.argumentTypes.length; i++) {
        if (method.argumentTypes[i] === 'pointer') {
          try {
            let obj = ObjC.Object(args[i]).toString()
            readable.push(obj)
          } catch (ex) {
            readable.push(args[i])
          }
        } else {
          readable.push(args[i])
        }
      }

      // Objective C's backtrace does not contain valuable information,
      // so I removed it

      send({
        subject,
        event: 'objc-call',
        args: readable,
        clazz,
        sel,
        time,
      })
    },
    onLeave
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