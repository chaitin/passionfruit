'use strict'

import * as fs from 'frida-fs'

import { arrayFromNSArray, dictFromNSDictionary, toJSON } from './lib/nsdict'
import uuidv4 from './lib/uuid'
import libc from './lib/libc'

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
  const size = 10 * 1024 // max read size: 10k

  return new Promise((resolve, reject) => {
    let fd = libc.open(name, 0, 0)
    if (fd == -1)
      reject(new Error(`unable to open file ${path}`))

    let stream = new UnixInputStream(fd, { autoClose: true })
    stream.read(size).then(resolve).catch(reject)
  })
}

function upload(path) {
  let session = uuidv4()
  let stream = fs.createWriteStream(path)
  let handler = (message, data) => {
    // todo
    recv('upload_' + session, handler)
  }
}

function download(path) {
  const session = uuidv4()
  const name = Memory.allocUtf8String(path)
  const watermark = 4 * 1024
  const subject = 'download'
  const size = getDataAttrForPath(path).size

  const fd = libc.open(name, 0, 0)
  if (fd == -1)
    throw new Error(`unable to open file ${path}`)

  let stream = new UnixInputStream(fd, { autoClose: true })
  let index = -1
  let count = 0
  let progress = 0
  let read = () => {
    index++
    stream.read(watermark).then(buffer => {
      count += buffer.byteLength
      progress = count / size * 100

      send({
        subject,
        event: 'data',
        session,
        progress,
      }, buffer)

      if (buffer.byteLength === watermark) {
        setImmediate(read)
      } else {
        send({
          subject,
          event: 'end',
          session,
        })
      }
    }).catch(error => {
      send({
        subject,
        event: 'error',
        session,
        error: error.message,
      })
    })
  }
  send({
    subject,
    event: 'start',
    session,
  })
  setImmediate(read)
  return {
    size,
    session
  }
}

module.exports = {
  ls,
  home,
  plist,
  text,
  download,
}