import { arrayFromNSArray, dictFromNSDictionary, toJSON } from './lib/nsdict'

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


function plist(path) {
  try {
    let info = ObjC.classes.NSDictionary.dictionaryWithContentsOfFile_(path)
    return toJSON(info)
  } catch (ex) {
    console.debug('agent internal error')
    console.error(ex)
    throw new Error(`unable to parse file ${path} as plist,
      please make sure it does exist and is in valid format`)
  }
}

function text(path) {
  const name = Memory.allocUtf8String(path)
  const size = 1024 // max read size: 1k

  let pOpen = Module.findExportByName(null, 'open')
  if (!pOpen)
    throw new Error('unable to resolve syscalls')

  const open = new NativeFunction(pOpen, 'int', ['pointer', 'int', 'int'])
  return new Promise((resolve, reject) => {
    let fd = open(name, 0, 0)
    if (fd == -1)
      reject(new Error(`unable to open file ${path}`))

    let stream = new UnixInputStream(fd, { autoClose: true })
    stream.read(size).then(resolve).catch(reject)
  })
}

module.exports = {
  ls,
  home,
  plist,
  text,
}