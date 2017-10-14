const { UIDebuggingInformationOverlay, LAContext, UIWindow } = ObjC.classes

function dumpWindow() {
  return UIWindow.keyWindow().recursiveDescription().toString()
}

let originalImplementation = null


function toggleTouchID(enable) {
  const subject = 'touchid'
  if (!LAContext)
    return {
      status: 'error',
      reason: 'Touch ID may not be supported by this device',
    }

  const method = LAContext['- evaluatePolicy:localizedReason:reply:']
  if (originalImplementation && !enable) {
    method.implementation = originalImplementation
    originalImplementation = null
    return {
      status: 'ok',
      reason: 'Successfully re-enabled touch id',
    }
  } else if (!originalImplementation && enable) {
    originalImplementation = method.implementation
    method.implementation = ObjC.implement(method, (self, sel, policy, reason, reply) => {
      const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
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
    return {
      status: 'ok',
      reason: 'Successfully disabled touch id',
    }
  }
  return {
    status: 'error',
    reason: 'invalid on/off argument',
  }
}

let overlay = null
function toggleDebugOverlay() {
  const p = Module.findExportByName('CoreFoundation', 'kCFCoreFoundationVersionNumber')
  const version = Memory.readDouble(p)

  if (version < 1300)
    throw new Error(`iOS version ${version} lower than expected, the feature is unavailable`)

  ObjC.schedule(ObjC.mainQueue, () => {
    if (overlay === null) {
      UIDebuggingInformationOverlay.prepareDebuggingOverlay()
      overlay = UIDebuggingInformationOverlay.overlay()
    }
    overlay.toggleVisibility()
  })
}

module.exports = {
  dumpWindow,
  toggleTouchID,
  toggleDebugOverlay,
}
