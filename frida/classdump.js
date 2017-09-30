exports.classes = function() {
  return Object.keys(ObjC.classes)
}

exports.methods = function methods(clazz) {
  return ObjC.classes[clazz].$ownMethods
}

exports.proto = function proto(clazz) {
  let chain = []
  let clz = ObjC.classes[clazz]
  if (!clz)
    throw new Error(`class ${clazz} not found`)

  while (clz = clz.$superClass)
    chain.push(clz.$className)
  return chain
}

exports.inspect = function(clazz) {
  return {
    methods: methods(clazz),
    proto: proto(clazz),
  }
}