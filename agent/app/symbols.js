function uniqueAndDemangle(list) {
  const set = {}
  return list.filter((symbol) => {
    const key = symbol.address
    if (({}).hasOwnProperty.call(set, key))
      return false
    set[key] = true
    return true
  }).map((symbol) => {
    if (symbol.name.startsWith('_Z')) {
      const demangled = DebugSymbol.fromAddress(symbol.address).name
      return Object.assign(symbol, { demangled })
    }
    return symbol
  })
}

export const modules = () => Process.enumerateModulesSync()
export const imports = name => uniqueAndDemangle(Module.enumerateImportsSync(name
  || Process.enumerateModulesSync()[0].name))
export const exports = name => uniqueAndDemangle(Module.enumerateExportsSync(name))
