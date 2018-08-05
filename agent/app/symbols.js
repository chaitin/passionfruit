export const modules = () => Process.enumerateModules()
export const imports = name => Module.enumerateImportsSync(name)
export const exports = name => Module.enumerateExportsSync(name)
