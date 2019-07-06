import { dictFromNSDictionary } from './nsdict'
import { hasOwnProperty } from './utils'

const fileManager = ObjC.classes.NSFileManager.defaultManager()


function NSStringWrapper(name) {
  return function() {
    const func = new NativeFunction(Module.findExportByName(null, name), 'pointer', [])
    const result = func()
    return new ObjC.Object(result).toString()
  }
}

export const NSTemporaryDirectory = NSStringWrapper('NSTemporaryDirectory')
export const NSHomeDirectory = NSStringWrapper('NSHomeDirectory')


export function getDataAttrForPath(path) {
  const urlPath = ObjC.classes.NSURL.fileURLWithPath_(path)
  const dict = fileManager.attributesOfItemAtPath_error_(urlPath.path(), NULL)
  const result = {}
  if (!dict)
    return result

  const info = dictFromNSDictionary(dict)
  const lookup = {
    owner: 'NSFileOwnerAccountName',
    size: 'NSFileSize',
    creation: 'NSFileCreationDate',
    permission: 'NSFilePosixPermissions',
    type: 'NSFileType',
    group: 'NSFileGroupOwnerAccountName',
    modification: 'NSFileModificationDate',
    protection: 'NSFileProtectionKey'
  }

  for (const key in lookup) {
    if (hasOwnProperty(lookup, key) && lookup[key] in info)
      result[key] = info[lookup[key]]
  }


  return result
}
