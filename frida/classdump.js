/* eslint camelcase:0, no-cond-assign:0 */

function getOwnClasses(sort) {
  const free = new NativeFunction(Module.findExportByName(null, 'free'), 'void', ['pointer'])
  const objc_copyClassNamesForImage = new NativeFunction(Module.findExportByName(null, 'objc_copyClassNamesForImage'), 'pointer', ['pointer', 'pointer'])
  const p = Memory.alloc(Process.pointerSize)
  Memory.writeUInt(p, 0)
  const path = ObjC.classes.NSBundle.mainBundle().executablePath().UTF8String()
  const pPath = Memory.allocUtf8String(path)
  const pClasses = objc_copyClassNamesForImage(pPath, p)
  const count = Memory.readUInt(p)
  const classes = new Array(count)
  for (let i = 0; i < count; i++) {
    const pClassName = Memory.readPointer(pClasses.add(i * Process.pointerSize))
    classes[i] = Memory.readUtf8String(pClassName)
  }
  free(pClasses)
  return sort ? classes.sort() : classes
}

function getGlobalClasses(sort) {
  const classes = Object.keys(ObjC.classes)
  return sort ? classes.sort() : classes
}

let ownClasses = null
let globalClasses = null

exports.ownClasses = () => {
  if (!ownClasses)
    ownClasses = getOwnClasses(true)
  return ownClasses
}

exports.classes = () => {
  if (!globalClasses)
    globalClasses = getGlobalClasses(true)

  return globalClasses
}

exports.inspect = (clazz) => {
  const proto = []
  let clz = ObjC.classes[clazz]
  if (!clz)
    throw new Error(`class ${clazz} not found`)

  while (clz = clz.$superClass)
    proto.unshift(clz.$className)

  return {
    methods: ObjC.classes[clazz].$ownMethods,
    proto,
  }
}
