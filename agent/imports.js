module.exports = function imports(name) {
  return new Promise((resolve, reject) => {
    Process.enumerateModules({
      onMatch(module) {
        if (typeof name === 'string' && module.name.toLowerCase() !== name.toLowerCase())
          return ''

        // if name not given, use the main executable
        // otherwise find the matching one

        resolve(Module.enumerateImportsSync(module.name))
        return 'stop'
      },
      onComplete() {
        // should not reach here
        reject(new Error(`unable to find module: ${name}`))
      },
    })
  })
}
