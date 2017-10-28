import socketStream from 'socket.io-stream'

const SearchWorker = require('worker-loader!./worker.js')

export class AsyncSearch {
  constructor(list, key) {
    this.key = key
    this.worker = new SearchWorker()
    this.worker.onmessage = ({ data }) => {
      this.callbacks.forEach(cb => cb(data))
    }
    this.callbacks = new Set()
    this.update(list, key)
  }

  update(list) {
    this.list = list
    this.worker.postMessage({ action: 'update', payload: list, key: this.key })
    return this
  }

  search(needle) {
    this.query = needle
    this.worker.postMessage({ action: 'search', payload: needle })
    return this
  }

  onMatch(callback) {
    this.callbacks.add(callback)
    return this
  }
}

export function debounce(func, wait, immediate) {
  let timeout
  /* eslint func-names: 0 */
  return function(...args) {
    const context = this
    const later = () => {
      timeout = null
      if (!immediate) func.apply(context, args)
    }
    const callNow = immediate && !timeout
    clearTimeout(timeout)
    timeout = setTimeout(later, wait || 400)
    if (callNow) func.apply(context, args)
  }
}

export function humanFileSize(size) {
  if (isNaN(size)) return 'N/A'
  if (size == 0) return '0 kB'
  let i = Math.floor(Math.log(size) / Math.log(1024))
  return (size / Math.pow(1024, i)).toFixed(2) * 1 + ' ' + ['bytes', 'kB', 'MB', 'GB', 'TB'][i]
}


export function download(socket, file, mime) {
  const { path } = file

  return socket.call('download', path).then(({ session }) => {
    const dest = socketStream.createStream()
    const parts = []
    socketStream(socket).emit('download', dest, { session })

    return new Promise((resolve, reject) => {
      dest.on('data', data => parts.push(data)).on('end', () => {
        const blob = new Blob(parts, { type: mime || 'octet/stream' })
        let url = URL.createObjectURL(blob)
        resolve(url)
      }).on('error', reject)
    })
  })
}