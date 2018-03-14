const fs = require('fs')
const path = require('path')

const { promisify } = require('util')
const { Transform } = require('stream')

const socketStream = require('socket.io-stream')

const readFile = promisify(fs.readFile)
const Cache = require('./cache')
const { retry, uuidv4 } = require('./utils')


class DownloadStream extends Transform {
  _transform(chunk, encoding, next) {
    this.push(chunk)
    next()
  }
}

class Handler {
  wrap(key) {
    const method = this[key].bind(this)
    return async(data, ack) => {
      try {
        ack({
          status: 'ok',
          data: await method(data),
        })
      } catch (err) {
        console.error('Uncaught RPC', err.stack || err)
        ack({
          status: 'error',
          error: `${err}`,
        })
      }
    }
  }

  handleError(message, error) {
    console.error('error message from frida')
    console.error(message.stack || message)
    console.error(error)
  }

  async getAgent(name) {
    const prefix = path.join('..', 'agent', `${name}.bundle`)
    if (process.env.NODE_ENV === 'development') {
      const source = await readFile(require.resolve(`${prefix}.js`), 'utf8')
      return this.session.createScript(source)
    }
    const bytes = await readFile(require.resolve(`${prefix}.bin`))
    return this.session.createScriptFromBytes(bytes)
  }
}

class RpcHandler extends Handler {
  constructor(session, socket) {
    super()

    this.session = session
    this.socket = socket
    this.stream = socketStream(socket)
    this.cache = new Cache()
    this.transfer = new Map()
    this.userScripts = new Map()
    this.handleMessage()
  }

  async load() {
    const { socket } = this
    const script = await this.getAgent('app')
    script.events.listen('destroyed', () => {
      socket.emit('script_destroyed')
      socket.disconnect(true)
    })
    script.events.listen('message', (message, data) => {
      if (message.type === 'send')
        this.handleSend(message, data)
      else if (message.type === 'error')
        this.handleError(message, data)
    })

    await script.load()
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
        console.warn('does not support binary protocol yet, message payload:')
        console.warn(payload)
      }

      this.socket.emit('console', payload) // forward to browser
    }
  }

  handleMessage() {
    [
      'eval',
      'unload',

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
      'screenshot',
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

  async eval(source) {
    const uuid = uuidv4()
    const { socket } = this
    const script = await this.session.createScript(`
      rpc.exports.bootstrap = function(js) {
        // temp workaround for
        // https://github.com/frida/frida-node/pull/28
        // in case the output goes to server side console instead
        // being sent to frontend
        //
        // this is not a sandbox, do not waste your time on escaping it

        ['log', 'warn', 'error'].forEach(function(level) {
          console[level] = function() {
            send({
              subject: 'console.message',
              level: level,
              args: [].slice.call(arguments)
            });
          };
        });

        // wow, copied from frida-python
        try {
          const result = (1, eval)(js);
          if (result instanceof ArrayBuffer) {
            return result;
          } else {
            var type = (result === null) ? 'null' : typeof result;
            return [type, result];
          }
        } catch (e) {
          return ['error', e instanceof Error ? {
            name: e.name,
            message: e.message,
            stack: e.stack
          } : e + ''];
        }
      }
    `)

    script.events.listen('destroyed', () => {
      socket.emit('userScript', {
        subject: 'destroyed',
        uuid,
      })
    })

    script.events.listen('message', (message, data) => {
      const { type, payload } = message
      // forward to frontend
      socket.emit('userScript', {
        subject: 'message',
        uuid,
        type,
        payload,
        // binary data is not supported right now
        hasData: data !== null,
      })
    })

    try {
      await script.load()
      const { bootstrap } = await script.getExports()
      const result = await bootstrap(source)
      let [type, value] = result
      if (result instanceof Buffer) {
        type = 'arraybuffer'
        value = Buffer.from(result).toString('base64')
      }

      this.userScripts.set(uuid, script)

      if (type === 'error') {
        console.error('Uncaught user frida script', value.stack || value)
        return {
          status: 'failed',
          error: value,
        }
      }

      return {
        status: 'ok',
        uuid,
        type,
        value,
      }
    } catch (error) {
      console.error('Uncaught user frida script', error.stack || error)
      return {
        status: 'failed',
        error,
      }
    }
  }

  async unload(uuid) {
    const script = this.userScripts.get(uuid)
    if (script) {
      this.userScripts.delete(uuid)
      return script.unload()
    }
    throw new Error(`script not found: ${uuid}`)
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

  async screenshot() {
    return this.agent.screenshot()
  }
}

class SpringBoardHandler extends Handler {
  constructor(session, socket) {
    super()

    this.session = session
    this.socket = socket
    this.handleMessage()
  }

  async load() {
    const { socket } = this
    const script = await this.getAgent('springboard')
    await script.load()
    script.events.listen('destroyed', () => {
      socket.emit('script_destroyed')
      socket.disconnect(true)
    })
    script.events.listen('message', (message, data) => {
      if (message.type === 'error')
        this.handleError(message, data)
    })

    this.script = script
    this.agent = await script.getExports()
  }

  handleMessage() {
    [
      'uiopen',
      'urls',
    ].forEach(event => this.socket.on(event, this.wrap(event)))
  }

  async urls() {
    return this.agent.urls()
  }

  async uiopen(url) {
    return this.agent.uiopen(url)
  }
}

module.exports = {
  RpcHandler,
  SpringBoardHandler,
}
