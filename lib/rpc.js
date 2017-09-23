const fridaLoad = require('frida-load')

const Cache = require('./cache')
const { retry } = require('./utils')


module.exports = class RpcHandler {
  constructor(session, socket) {
    this.session = session
    this.socket = socket
    this.cache = new Cache()
    this.handleMessage()
  }

  async load() {
    let { socket } = this
    let source = await fridaLoad(require.resolve('../frida'))
    let script = await this.session.createScript(source)

    await script.load()
    script.events.listen('destroyed', () => {
      socket.emit('script_destroyed')
      socket.disconnect(true)
    })
    script.events.listen('message', (message, data) => {
      // todo
    })

    this.script = script
    this.agent = await script.getExports()
  }

  handleMessage() {
    const events = [
      'modules',
      'ranges',
      'exports',
      'classes',
      'methods',
      'info',
      'lsof',
      'imports',
      'ls',
      'plist',
    ]

    this._router = new Map()
    for (let event of events) {
      this.socket.on(event, this.wrap(event))
    }
  }

  wrap(key) {
    let method = this[key].bind(this)
    return async(data, ack) => {
      try {
        ack({
          status: 'ok',
          data: await method(data)
        })
      } catch (err) {
        console.error('rpc error', err)
        console.info(err.stack)
        ack({
          status: 'error',
          error: err + '',
        })
      }
    }
  }

  async modules() {
    return await this.session.enumerateModules()
  }

  async ranges({ protection }) {
    return await this.session.enumerateRanges(protection)
  }

  async exports({ module }) {
    return await session.enumerateExports(module)
  }

  async classes() {
    let func = this.agent.classes.bind(this.agent)
    return await this.cache.fetch('classes', func)
  }

  async methods({ clz }) {
    let func = this.agent.methods.bind(this.agent, clz)
    return await this.cache.fetch(`methods_${clz}`, func)
  }

  async info() {
    return await retry(async() => {
      let sec = await this.agent.checksec()
      let info = await this.agent.info()
      return { sec, info }
    })
  }

  async lsof() {
    return await this.agent.lsof()
  }

  async imports(data) {
    let name = (data && data.name) ? data.name : null
    return await this.agent.imports()
  }

  async ls(path) {
    return path ? await this.agent.ls(path) : await this.agent.home()
  }

  async plist(path) {
    return await this.agent.plist(path)
  }
}