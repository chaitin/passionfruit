const macho = require('macho')


module.exports = () => new Promise((resolve, reject) => {
  const result = {}

  const appModule = Process.enumerateModulesSync()[0]
  const rawHeaders = Buffer.from(Memory.readByteArray(appModule.base, Math.min(appModule.size, 65536)))
  const headers = macho.parse(rawHeaders)

  if (headers.flags.pie)
    result.pie = true

  const isEncrypted = headers.cmds.some(cmd => /^encryption_info_(32|64)$/.test(cmd.type) && cmd.id === 1)
  if (isEncrypted)
    result.encrypted = true

  const importNames = Module.enumerateImportsSync(appModule.path).reduce((names, imp) => {
    names.add(imp.name)
    return names
  }, new Set())

  if (importNames.has('__stack_chk_guard'))
    result.canary = true

  if (importNames.has('objc_release'))
    result.arc = true

  resolve(result)
})
