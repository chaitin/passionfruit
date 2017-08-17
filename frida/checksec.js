rpc.exports.main = function() {
  return new Promise((resolve, reject) => {

    Process.enumerateModules({
      onMatch: function(module) {
        var result = {
          canary: false,
          arc: false,
        }

        Module.enumerateImports(module.name, {
          onMatch: function(imp) {
            if (imp.name == '__stack_chk_guard')
              result.canary = true

            if (imp.name == 'objc_release')
              result.arc = true
          },
          onComplete: function() {

            console.log(JSON.stringify(result))
          }
        })

        return 'stop'
      },
      onComplete: function() {}
    })

  })
}