import socketStream from 'socket.io-stream'

const SearchWorker = require('worker-loader!./worker.js')

import { DOWNLOADING, SET_DOWNLOAD_TOTAL, UPDATE_BYTES } from '~/vuex/types'
import state from '~/vuex'


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

  if (state.getters[DOWNLOADING])
    return Promise.reject('only one task allowed at the same time')

  return socket.call('download', path).then(({ session, size }) => {
    const dest = socketStream.createStream()
    const parts = []
    state.commit(DOWNLOADING, true)
    state.commit(SET_DOWNLOAD_TOTAL, size)
    socketStream(socket).emit('download', dest, { session })

    return new Promise((resolve, reject) => {
      dest.on('data', chunk => {
        state.commit(UPDATE_BYTES, chunk.length)
        parts.push(chunk)
      }).on('end', () => {
        const blob = new Blob(parts, { type: mime || 'octet/stream' })
        let url = URL.createObjectURL(blob)
        state.commit(DOWNLOADING, false)
        resolve(url)
      }).on('error', reject)
    })
  })
}