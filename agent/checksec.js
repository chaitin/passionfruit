import macho from 'macho'

import ReadOnlyMemoryBuffer from './lib/romembuffer'


module.exports = () => new Promise((resolve, reject) => {
  const result = {}

  const [appModule, ] = Process.enumerateModulesSync()
  const buffer = new ReadOnlyMemoryBuffer(appModule.base, appModule.size)
  const headers = macho.parse(buffer)

  if (headers.flags.pie)
    result.pie = true

  const isEncrypted = headers.cmds.some(cmd => /^encryption_info_(32|64)$/.test(cmd.type) && cmd.id === 1)
  if (isEncrypted)
    result.encrypted = true

  const importNames = Module.enumerateImportsSync(appModule.path).reduce((names, imp) => {
    names.add(imp.name)
    return names
  }, new Set())

  result.canary = importNames.has('__stack_chk_guard')
  result.arc = importNames.has('objc_release')

  resolve(result)
})
