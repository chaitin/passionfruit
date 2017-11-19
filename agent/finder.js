import { arrayFromNSArray, dictFromNSDictionary, toJSON } from './lib/nsdict'
import { hasOwnProperty } from './lib/utils'
import uuidv4 from './lib/uuid'
import libc from './lib/libc'
import { getDataAttrForPath } from './lib/foundation'


const fileManager = ObjC.classes.NSFileManager.defaultManager()


function ls(path) {
  let list = fileManager.directoryContentsAtPath_(path)
  const isDir = Memory.alloc(Process.pointerSize)

  if (!list)
    return { path, list: [] }
  list = arrayFromNSArray(list).map((filename) => {
    const fullPath = `${path}/${filename}`
    fileManager.fileExistsAtPath_isDirectory_(fullPath, isDir)

    return {
      /* eslint eqeqeq:0 */
      type: Memory.readPointer(isDir) == 0 ? 'file' : 'directory',
      name: filename,
      path: fullPath,
      attribute: getDataAttrForPath(fullPath) || {},
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
    const info = ObjC.classes.NSDictionary.dictionaryWithContentsOfFile_(path)
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
    const fd = libc.open(name, 0, 0)
    if (fd === -1)
      reject(new Error(`unable to open file ${path}`))

    const stream = new UnixInputStream(fd, { autoClose: true })
    stream.read(size).then(resolve).catch(reject)
  })
}


function download(path) {
  const session = uuidv4()
  const name = Memory.allocUtf8String(path)
  const watermark = 4 * 1024
  const subject = 'download'
  const { size } = getDataAttrForPath(path)

  const fd = libc.open(name, 0, 0)
  if (fd === -1)
    throw new Error(`unable to open file ${path}`)

  const stream = new UnixInputStream(fd, { autoClose: true })
  const read = () => {
    stream.read(watermark).then((buffer) => {
      send({
        subject,
        event: 'data',
        session,
      }, buffer)

      if (buffer.byteLength === watermark)
        setImmediate(read)
      else
        send({
          subject,
          event: 'end',
          session,
        })
    }).catch((error) => {
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
    session,
  }
}

module.exports = {
  ls,
  home,
  plist,
  text,
  download,
}
