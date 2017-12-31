const { Transform } = require('stream')

const socketStream = require('socket.io-stream')
const fs = require('fs')
const { promisify } = require('util')

const readFile = promisify(fs.readFile)

const Cache = require('./cache')
const { retry } = require('./utils')


class DownloadStream extends Transform {
  _transform(chunk, encoding, next) {
    this.push(chunk)
    next()
  }
}

module.exports = class RpcHandler {
  constructor(session, socket) {
    this.session = session
    this.socket = socket
    this.stream = socketStream(socket)
    this.cache = new Cache()
    this.transfer = new Map()
    this.handleMessage()
  }

  async load() {
    const { socket } = this
    const source = await readFile(require.resolve('../_agent'), 'utf8')
    const script = await this.session.createScript(source)

    await script.load()
    script.events.listen('destroyed', () => {
      socket.emit('script_destroyed')
      socket.disconnect(true)
    })
    script.events.listen('message', (message, data) => {
      if (message.type === 'send') {
        this.handleSend(message, data)
      } else if (message.type === 'error') {
        this.handleError(message, data)
      }
    })

    this.script = script
    this.agent = await script.getExports()
  }

  handleSend({ payload }, data) {
    if (payload.subject === 'download') {
      const { event, session } = payload
      if (event === 'start') {
        const stream = new DownloadStream()
        this.transfer.set(session, stream)
      } else if (event === 'end') {
        const stream = this.transfer.get(session)
        stream.end()
      } else if (event === 'data') {
        const stream = this.transfer.get(session)
        stream.write(data)
      }
    } else {
      if (data !== null) {
        console.warning('does not support binary protocol yet, message payload:')
        console.warning(payload)
      }

      this.socket.emit('console', payload) // forward to browser
    }
  }

  handleError(message, error) {
    console.error('error message from frida')
    console.error(message)
    console.error(error)
  }

  handleMessage() {
    [
      'modules',
      'exports',

      'classes',
      'ownClasses',
      'inspect',

      'info',
      'userDefaults',
      'imports',

      'ls',
      'plist',
      'text',
      'download',

      'tables',
      'data',

      'dumpWindow',
      'toggleDebugOverlay',

      'dumpKeyChain',
      'cookies',

      'hook',
      'unhook',
      'swizzle',
      'unswizzle',

      'dumpdecrypted',
    ].forEach(event => this.socket.on(event, this.wrap(event)))

    // handle file transfer
    this.stream.on('download', (stream, args) => {
      const { session } = args
      if (session && this.transfer.has(session)) {
        const source = this.transfer.get(session)
        source.pipe(stream).on('finish', () => this.transfer.delete(session))
      }
    })
  }

  wrap(key) {
    const method = this[key].bind(this)
    return async(data, ack) => {
      try {
        ack({
          status: 'ok',
          data: await method(data),
        })
      } catch (err) {
        console.error('rpc error', err)
        console.info(err.stack)
        ack({
          status: 'error',
          error: `${err}`,
        })
      }
    }
  }

  async modules() {
    return this.session.enumerateModules()
  }

  async exports({ module }) {
    return this.session.enumerateExports(module)
  }

  async classes() {
    const func = this.agent.classes.bind(this.agent)
    return this.cache.fetch('classes', func)
  }

  async ownClasses() {
    const func = this.agent.ownClasses.bind(this.agent)
    return this.cache.fetch('ownClasses', func)
  }

  async inspect({ clz }) {
    const func = this.agent.inspect.bind(this.agent, clz)
    return this.cache.fetch(`inspect_${clz}`, func)
  }

  async info() {
    return retry(async() => {
      const sec = await this.agent.checksec()
      const info = await this.agent.info()
      return { sec, info }
    })
  }

  async userDefaults() {
    return this.agent.userDefaults()
  }

  async imports(data) {
    const name = (data && data.name) ? data.name : null
    return this.agent.imports(name)
  }

  async ls(path) {
    return path ? this.agent.ls(path) : this.agent.home()
  }

  async plist(path) {
    return this.agent.plist(path)
  }

  async text(path) {
    return this.agent.text(path)
  }

  async tables(path) {
    return this.agent.tables(path)
  }

  async data(arg) {
    return this.agent.data(arg)
  }

  async download(path) {
    return this.agent.download(path)
  }

  async dumpWindow() {
    return this.agent.dumpWindow()
  }

  async toggleDebugOverlay() {
    return this.agent.toggleDebugOverlay()
  }

  async dumpKeyChain() {
    return this.agent.dumpKeyChain()
  }

  async cookies() {
    return this.agent.cookies()
  }

  async hook({ module, name, args, ret }) {
    return this.agent.hook(module, name, { args, ret })
  }

  async unhook({ module, name }) {
    return this.agent.unhook(module, name)
  }

  async swizzle({ clazz, method, ret }) {
    return this.agent.swizzle(clazz, method, ret)
  }

  async unswizzle({ clazz, method }) {
    return this.agent.unswizzle(clazz, method)
  }

  async dumpdecrypted(name) {
    return this.agent.dumpdecrypted(name)
  }
}
