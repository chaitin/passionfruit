/* eslint no-cond-assign:0 */

export function getOwnClasses(sort) {
  const free = new NativeFunction(Module.findExportByName(null, 'free'), 'void', ['pointer'])
  const copyClassNamesForImage = new NativeFunction(Module.findExportByName(null,
    'objc_copyClassNamesForImage'), 'pointer', ['pointer', 'pointer'])
  const p = Memory.alloc(Process.pointerSize)
  Memory.writeUInt(p, 0)
  const path = ObjC.classes.NSBundle.mainBundle().executablePath().UTF8String()
  const pPath = Memory.allocUtf8String(path)
  const pClasses = copyClassNamesForImage(pPath, p)
  const count = Memory.readUInt(p)
  const classesArray = new Array(count)
  for (let i = 0; i < count; i++) {
    const pClassName = Memory.readPointer(pClasses.add(i * Process.pointerSize))
    classesArray[i] = Memory.readUtf8String(pClassName)
  }
  free(pClasses)
  return sort ? classesArray.sort() : classesArray
}

function getGlobalClasses(sort) {
  const classesArray = Object.keys(ObjC.classes)
  return sort ? classesArray.sort() : classesArray
}

let cachedOwnClasses = null
let cachedGlobalClasses = null

export function ownClasses() {
  if (!cachedOwnClasses)
    cachedOwnClasses = getOwnClasses(true)
  return cachedOwnClasses
}

export function classes() {
  if (!cachedGlobalClasses)
    cachedGlobalClasses = getGlobalClasses(true)

  return cachedGlobalClasses
}

export function inspect(clazz) {
  const proto = []
  let clz = ObjC.classes[clazz]
  if (!clz)
    throw new Error(`class ${clazz} not found`)

  while (clz = clz.$superClass)
    proto.unshift(clz.$className)

  return {
    methods: ObjC.classes[clazz].$ownMethods,
    proto
  }
}
