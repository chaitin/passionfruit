class Cache {
  constructor(opt) {
    this.timeout = (opt || {}).timeout || 3600
    this.values = new Map()
  }

  async fetch(key, fresh) {
    const now = Math.floor((new Date()).getTime() / 1000)
    const v = this.values
    if (v.has(key) && v.get(key).expire > now) {
      return v.get(key).value
    }
    const val = await fresh()
    v.set(key, { value: val, expire: now + this.timeout })
    return val
  }
}

module.exports = Cache
