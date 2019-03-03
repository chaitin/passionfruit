function uniqueAndDemangle(list) {
  const set = new Set()
  return list.filter((symbol) => {
    const key = symbol.address
    if (set.has(key))
      return false
    set.add(key)
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
