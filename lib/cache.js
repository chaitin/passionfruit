class Cache{
  constructor(opt) {
    opt = opt || {}
    this._timeout = opt.timeout || 3600
    this._values = new Map()
  }

  async fetch(key, fresh) {
    let now = ~~((new Date()).getTime() / 1000)
    let v = this._values
    if (v.has(key) && v.get(key).expire > now) {
      return v.get(key).value
    } else {
      let val = await fresh()
      v.set(key, {value: val, expire: now + this._timeout})
      return val
    }
  }
}

module.exports = Cache
