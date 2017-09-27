'use strict'

function dumpWindow() {
  return ObjC.classes.UIWindow.keyWindow().recursiveDescription().toString()
}

let resolver = new ApiResolver('objc')
let LAContext_evaluatePolicy_localizedReason_reply = {}
let touchIDHook = null

resolver.enumerateMatches('-[LAContext evaluatePolicy:localizedReason:reply:]', {
  onMatch: function(match) {
    LAContext_evaluatePolicy_localizedReason_reply.name = match.name
    LAContext_evaluatePolicy_localizedReason_reply.address = match.address
  },
  onComplete: function() {}
})

function toggleTouchID(on) {
  const subject = 'touchid'
  if (!LAContext_evaluatePolicy_localizedReason_reply.address) {
    return {
      status: 'error',
      reason: 'Touch ID may not be supported by this device'
    }
  }
  
  if (touchIDHook && !on) {
    touchIDHook.detach()
    return {
      status: 'ok',
      reason: 'successfully detached touch id bypass'
    }
  } else if (!touchIDHook && on) {
    touchIDHook = Interceptor.attach(LAContext_evaluatePolicy_localizedReason_reply.address, {
      onEnter: function (args) {
        let reason = new ObjC.Object(args[3])
        send({
          subject,
          event: 'request',
          reason,
          // todo: backtrace
        })

        let originalBlock = new ObjC.Block(args[4])
        let savedReplyBlock = originalBlock.implementation
        originalBlock.implementation = function(success, error) {
          send({
            subject,
            event: 'success',
            response: success,
            error,
          })

          if (!success) {
            send({
              subject,
              event: 'bypass',
            })
          }

          savedReplyBlock(true, error)
        }
      }
    })

    return {
      status: 'ok',
      reason: 'successfully set touch id bypass'
    }
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