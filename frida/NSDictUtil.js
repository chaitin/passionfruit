
function toJSON(value) {
  if (value === null)
    return value

  if (value.isKindOfClass_(ObjC.classes.NSArray))
    return arrayFromNSArray(value)
  else if (value.isKindOfClass_(ObjC.classes.NSDictionary))
    return dictFromNSDictionary(value)
  else
    return value.toString()
}

function dictFromNSDictionary(nsDict) {
  const jsDict = {}
  const keys = nsDict.allKeys()
  const count = keys.count()
  for (let i = 0; i < count; i++) {
    let key = keys.objectAtIndex_(i)
    let value = nsDict.objectForKey_(key)
    jsDict[key.toString()] = toJSON(value)
  }

  return jsDict
}

function arrayFromNSArray(nsArray) {
  const arr = []
  const count = nsArray.count()
  for (let i = 0; i < count; i++) {
    let val = nsArray.objectAtIndex_(i)
    arr.push(toJSON(val))
  }
  return arr
}

// todo: refactor me
//
// function infoDictionary() {
//   if (ObjC.available && 'NSBundle' in ObjC.classes) {
//     let info = ObjC.classes.NSBundle.mainBundle().infoDictionary()
//     return dictFromNSDictionary(info)
//   }
//   return null
// }

// function infoLookup(key) {
//   if (ObjC.available && 'NSBundle' in ObjC.classes) {
//     let info = ObjC.classes.NSBundle.mainBundle().infoDictionary()
//     let value = info.objectForKey_(key)
//     if (value === null) {
//       return value
//     } else if (value.class().toString() === '__NSCFArray') {
//       return arrayFromNSArray(value)
//     } else if (value.class().toString() === '__NSCFDictionary') {
//       return dictFromNSDictionary(value)
//     } else {
//       return value.toString()
//     }
//   }
//   return null
// }

module.exports = {
  dictFromNSDictionary,
  arrayFromNSArray,
  // infoDictionary,
  // infoLookup,
  toJSON,
}