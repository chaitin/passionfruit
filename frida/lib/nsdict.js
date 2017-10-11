/* eslint no-use-before-define:0 */
import { hasOwnProperty } from './utils'

const {
  NSMutableDictionary,
  NSArray,
  NSDictionary,
  NSMutableArray,
  NSNumber,
  NSString,
  NSNull,
  __NSCFBoolean,
} = ObjC.classes


function toJSON(value) {
  if (value === null || typeof value !== 'object')
    return value

  if (value.isKindOfClass_(NSArray))
    return arrayFromNSArray(value)
  else if (value.isKindOfClass_(NSDictionary))
    return dictFromNSDictionary(value)
  else if (value.isKindOfClass_(NSNumber))
    return value.floatValue()

  return value.toString()
}

function dictFromNSDictionary(nsDict) {
  const jsDict = {}
  const keys = nsDict.allKeys()
  const count = keys.count()
  for (let i = 0; i < count; i++) {
    const key = keys.objectAtIndex_(i)
    const value = nsDict.objectForKey_(key)
    jsDict[key.toString()] = toJSON(value)
  }

  return jsDict
}

function arrayFromNSArray(nsArray) {
  const arr = []
  const count = nsArray.count()
  for (let i = 0; i < count; i++) {
    const val = nsArray.objectAtIndex_(i)
    arr.push(toJSON(val))
  }
  return arr
}

function toNSObject(obj) {
  // not tested, may be buggy
  if ('isKindOfClass_' in obj)
    return obj

  if (typeof obj === 'boolean')
    return __NSCFBoolean.numberWithBool_(obj)

  if (typeof obj === 'undefined' || obj === null)
    return NSNull.null()

  if (typeof obj === 'string')
    return NSString.stringWithString_(obj)

  if (Array.isArray(obj)) {
    const mutableArray = NSMutableArray.alloc().init()
    obj.forEach(item => mutableArray.addObject_(toNSObject(item)))
    return mutableArray
  }

  const mutableDict = NSMutableDictionary.alloc().init()
  for (const key in obj)
    if (hasOwnProperty(obj, key)) {
      const val = toNSObject(obj[key])
      mutableDict.setObject_forKey_(val, key)
    }

  return mutableDict
}


module.exports = {
  dictFromNSDictionary,
  arrayFromNSArray,
  toJSON,
  toNSObject,
}
