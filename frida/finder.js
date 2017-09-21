import { arrayFromNSArray, dictFromNSDictionary } from './lib/nsdict'

const fileManager = ObjC.classes.NSFileManager.defaultManager()


function getDataAttrForPath(path) {
  let urlPath = ObjC.classes.NSURL.fileURLWithPath_(path)
  let dict = fileManager.attributesOfItemAtPath_error_(urlPath.path(), NULL)
  if (!dict) return dict
  let info = dictFromNSDictionary(dict)
  let lookup = {
    owner: 'NSFileOwnerAccountName',
    size: 'NSFileSize',
    creation: 'NSFileCreationDate',
    permission: 'NSFilePosixPermissions',
    type: 'NSFileType',
    group: 'NSFileGroupOwnerAccountName',
    modification: 'NSFileModificationDate',
    protection: 'NSFileProtectionKey',
  }
  let result = {}
  for (let key in lookup)
    if (lookup.hasOwnProperty(key) && lookup[key] in info)
      result[key] = info[lookup[key]]

  return result
}


function ls(path) {
  let list = fileManager.directoryContentsAtPath_(path)
  let isDir = Memory.alloc(Process.pointerSize)

  list = arrayFromNSArray(list).map(filename => {
    let fullPath = path + '/' + filename
    fileManager.fileExistsAtPath_isDirectory_(fullPath, isDir)

    return {
      type: Memory.readPointer(isDir) == 0 ? 'file' : 'directory',
      name: filename,
      path: fullPath,
      attribute: getDataAttrForPath(fullPath),
    }
  })

  return { path, list }
}

function home() {
  const path = ObjC.classes.NSProcessInfo.processInfo().environment().objectForKey_('HOME').toString()
  return ls(path)
}

module.exports = {
  ls,
  home,
}