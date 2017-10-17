class Cache {
  constructor(opt) {
    this.timeout = (opt || {}).timeout || 3600
    this.values = new Map()
  }

  async fetch(key, fresh) {
    const v = this.values
    if (v.has(key))
      return v.get(key)

    const val = await fresh()
    v.set(key, val)
    setTimeout(() => v.delete(key), this.timeout * 1000)
    return val
  }
}

module.exports = Cache
