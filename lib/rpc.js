'use strict'
const { tmpdir } = require('os')
const { Transform } = require('stream')

const socketStream = require('socket.io-stream')
const fridaLoad = require('frida-load')

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
    let { socket } = this
    let source = await fridaLoad(require.resolve('../frida'))
    let script = await this.session.createScript(source)

    await script.load()
    script.events.listen('destroyed', () => {
      socket.emit('script_destroyed')
      socket.disconnect(true)
    })
    script.events.listen('message', (message, data) => {
      if (message.type == 'send') {
        this.handleSend(message, data)
      } else if (message.type == 'error') {
        this.handleError(message, data)
      }
    })

    this.script = script
    this.agent = await script.getExports()
  }

  handleSend({ type, payload }, data) {
    if (payload.subject === 'download') {
      let { event, session } = payload
      if (event === 'start') {
        let stream = new DownloadStream()
        this.transfer.set(session, stream)
      } else if (event === 'end') {
        let stream = this.transfer.get(session)
        stream.end()
      } else if (event === 'data') {
        let stream = this.transfer.get(session)
        stream.write(data)
      }
    } else {
      if (data !== null) {
        console.warning(`does not support binary protocol yet, message payload:`)
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
    const events = [
      'modules',
      'exports',

      'classes',
      'ownClasses',
      'inspect',

      'info',
      'lsof',
      'imports',

      'ls',
      'plist',
      'text',
      'download',

      'tables',
      'data',

      'dumpWindow',

      'dumpKeyChain',
      'cookies',

      'hook',
      'unhook',
      'swizzle',
      'unswizzle',
    ]

    for (let event of events) {
      this.socket.on(event, this.wrap(event))
    }

    // handle file transfer
    this.stream.on('download', (stream, args) => {
      let { session } = args
      if (session && this.transfer.has(session)) {
        let source = this.transfer.get(session)
        source.pipe(stream).on('finish', () => this.transfer.delete(session))
      }
    })
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

  async exports({ module }) {
    return await this.session.enumerateExports(module)
  }

  async classes() {
    let func = this.agent.classes.bind(this.agent)
    return await this.cache.fetch('classes', func)
  }

  async ownClasses() {
    let func = this.agent.ownClasses.bind(this.agent)
    return await this.cache.fetch('ownClasses', func)
  }

  async inspect({ clz }) {
    let func = this.agent.inspect.bind(this.agent, clz)
    return await this.cache.fetch(`inspect_${clz}`, func)
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

  async text(path) {
    return await this.agent.text(path)
  }

  async tables(path) {
    return await this.agent.tables(path)
  }

  async data(arg) {
    return await this.agent.data(arg)
  }

  async download(path) {
    return await this.agent.download(path)
  }

  async dumpWindow() {
    return await this.agent.dumpWindow()
  }

  async dumpKeyChain() {
    return await this.agent.dumpKeyChain()
  }

  async cookies() {
    return await this.agent.cookies()
  }

  async hook({ module, name, args, ret }) {
    return await this.agent.hook(module, name, { args, ret })
  }

  async unhook({ module, name }) {
    return await this.agent.unhook(module, name)
  }

  async swizzle({ clazz, method, ret }) {
    return await this.agent.swizzle(clazz, method, ret)
  }

  async unswizzle({ clazz, method }) {
    return await this.agent.unswizzle(clazz, method)
  }
}