const SearchWorker = require('worker-loader!./worker.js')


export class AsyncSearch {
  constructor(list, key) {
    this.key = key
    this.worker = new SearchWorker()
    this.worker.onmessage = ({data}) => {
      this.callbacks.forEach(cb => cb(data))
    }
    this.callbacks = new Set()
    this.update(list, key)
  }

  update(list) {
    this.list = list
    this.worker.postMessage({action: 'update', payload: list, key: this.key})
  }

  search(needle) {
    this.query = needle
    this.worker.postMessage({action: 'search', payload: needle})
  }

  onMatch(callback) {
    this.callbacks.add(callback)
  }
}

export function debounce(func, wait, immediate) {
  let timeout
  return function() {
    let context = this, args = arguments
    let later = function() {
      timeout = null
      if (!immediate) func.apply(context, args)
    }
    let callNow = immediate && !timeout
    clearTimeout(timeout)
    timeout = setTimeout(later, wait || 400)
    if (callNow) func.apply(context, args)
  }
}