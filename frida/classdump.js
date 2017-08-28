exports.classes = function() {
  return Object.keys(ObjC.classes)
}

exports.methods = function(clazz) {
  return ObjC[clazz].$methods
}

