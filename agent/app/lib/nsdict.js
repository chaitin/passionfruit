/* eslint no-use-before-define:0 */
import { hasOwnProperty } from './utils'

// workaround for #17
// eslint-disable-next-line
null;


const {
  NSMutableDictionary,
  NSArray,
  NSData,
  NSDictionary,
  NSMutableArray,
  NSNumber,
  NSString,
  NSNull,
  NSPropertyListSerialization,
  __NSCFBoolean
} = ObjC.classes

const NSPropertyListImmutable = 0


export function toJSON(value) {
  if (value === null || typeof value !== 'object')
    return value
  if (value.isKindOfClass_(NSArray))
    return arrayFromNSArray(value)
  if (value.isKindOfClass_(NSDictionary))
    return dictFromNSDictionary(value)
  if (value.isKindOfClass_(NSNumber))
    return value.floatValue()
  return value.toString()
}

export function dictFromNSDictionary(nsDict) {
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

export function dictFromPlistCharArray(address, size) {
  const format = Memory.alloc(Process.pointerSize)
  const err = Memory.alloc(Process.pointerSize)
  const data = NSData.dataWithBytesNoCopy_length_(address, size)
  // it is ObjectiveC's fault for the long line
  // eslint-disable-next-line
  const dict = NSPropertyListSerialization.propertyListFromData_mutabilityOption_format_errorDescription_(
    data,
    NSPropertyListImmutable,
    format,
    err,
  )

  const desc = Memory.readPointer(err)
  if (!desc.isNull())
    throw new Error(new ObjC.Object(desc))

  return dictFromNSDictionary(dict)
}

export function arrayFromNSArray(nsArray, max) {
  const arr = []
  const count = nsArray.count()
  const len = Number.isNaN(max) ? Math.min(count, max) : count
  for (let i = 0; i < len; i++) {
    const val = nsArray.objectAtIndex_(i)
    arr.push(toJSON(val))
  }
  return arr
}

export function toNSObject(obj) {
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
  for (const key in obj) {
    if (hasOwnProperty(obj, key)) {
      const val = toNSObject(obj[key])
      mutableDict.setObject_forKey_(val, key)
    }
  }

  return mutableDict
}
