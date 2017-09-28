'use strict'

function dumpWindow() {
  return ObjC.classes.UIWindow.keyWindow().recursiveDescription().toString()
}

let originalImplementation = null


function toggleTouchID(enable) {
  const subject = 'touchid'
  const { LAContext } = ObjC.classes
  if (!LAContext) {
    return {
      status: 'error',
      reason: 'Touch ID may not be supported by this device'
    }
  }

  const method = LAContext['- evaluatePolicy:localizedReason:reply:']
  if (originalImplementation && !enable) {
    method.implementation = originalImplementation
    originalImplementation = null

    return {
      status: 'ok',
      reason: 'Successfully re-enabled touch id'
    }
  } else if (!originalImplementation && enable) {
    originalImplementation = method.implementation
    method.implementation = ObjC.implement(method, function(self, sel, policy, reason, reply) {
      let backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress).filter(e => e.name)

      send({
        subject,
        event: 'request',
        reason,
        backtrace,
      })

      // dismiss the dialog
      const callback = new ObjC.Block(ptr(reply))
      callback.implementation(1, null)
    })
  } else {
    return {
      status: 'error',
      reason: 'invalid on/off argument'
    }
  }
}

module.exports = {
  dumpWindow,
  toggleTouchID,
}