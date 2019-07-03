function dumpWindow() {
  try {
    return ObjC.classes.UIWindow.keyWindow().recursiveDescription().toString()
  } catch (e) {
    return 'Error: unable to fetch UIWindow description, please wait for few seconds and retry'
  }
}

let originalImplementation = null


function toggleTouchID(enable) {
  if (!Process.findModuleByName('LocalAuthentication'))
    return

  Module.ensureInitialized('LocalAuthentication')

  const { LAContext } = ObjC.classes
  const subject = 'touchid'
  if (!LAContext)
    throw new Error('Touch ID may not be supported by this device')

  const method = LAContext['- evaluatePolicy:localizedReason:reply:']
  if (originalImplementation && enable) {
    method.implementation = originalImplementation
    originalImplementation = null

    send({
      subject,
      event: 'on',
      reason: 're-eanbled touch id',
      date: new Date()
    })
  } else if (!originalImplementation && !enable) {
    originalImplementation = method.implementation
    method.implementation = ObjC.implement(method, (self, sel, policy, reason, reply) => {
      send({
        subject,
        event: 'request',
        reason,
        date: new Date()
      })

      // dismiss the dialog
      const callback = new ObjC.Block(ptr(reply))
      callback.implementation(1, null)
    })

    send({
      subject,
      event: 'off',
      reason: 'successfully disabled touch id',
      date: new Date()
    })
  } else {
    throw new Error('invalid on/off argument')
  }
}

module.exports = {
  dumpWindow,
  toggleTouchID
}
