class Cache {
  constructor(opt) {
    opt = opt || {}
    this._timeout = opt.timeout || 3600
    this._values = new Map()
  }

  fetch(key, fresh) {
    let now = ~~((new Date()).getTime() / 1000)
    if (this.has(key) && this.get(key).expire > now) {
      return this.get(key).value
    } else {
      this.set(key, {value: fresh(), expire: now + this._timeout})
    }
  }
}

module.exports = Cache
