function getOwnClasses(sort) {
  const free = new NativeFunction(Module.findExportByName(null, 'free'), 'void', ['pointer'])
  const objc_copyClassNamesForImage = new NativeFunction(Module.findExportByName(
    null, 'objc_copyClassNamesForImage'), 'pointer', ['pointer', 'pointer'])
  const classes = new Array(count)
  const p = Memory.alloc(Process.pointerSize)
  Memory.writeUInt(p, 0)
  const path = ObjC.classes.NSBundle.mainBundle().executablePath().UTF8String()
  const pPath = Memory.allocUtf8String(path)
  const pClasses = objc_copyClassNamesForImage(pPath, p)
  const count = Memory.readUInt(p)
  for (let i = 0; i < count; i++) {
    let pClassName = Memory.readPointer(pClasses.add(i * Process.pointerSize))
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

exports.ownClasses = function() {
  if (!ownClasses)
    ownClasses = getOwnClasses(true)
  return ownClasses
}

exports.classes = function() {
  if (!globalClasses)
    globalClasses = getGlobalClasses(true)

  return globalClasses
}

exports.inspect = function(clazz) {
  let proto = []
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