module.exports = function(name) {
  return new Promise((resolve, reject) => {
    Process.enumerateModules({
      onMatch: function(module) {
        if (typeof name === 'string' && module.name.toLowerCase() != name.toLowerCase()) {
          return
        }

        // if name not given, use the main executable
        // otherwise find the matching one

        let imports = Module.enumerateImportsSync(module.name)
        resolve(imports)
        return 'stop'
      },
      onComplete: function() {
        // should not reach here
        reject(new Error('unable to find module: ' + name))
      }
    })
  })
}