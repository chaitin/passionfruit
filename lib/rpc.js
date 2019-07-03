const fs = require('fs')
const os = require('os')
const path = require('path')
const net = require('net')

const { promisify } = require('util')
const { Transform, Writable } = require('stream')

const createSocketStream = require('socket.io-stream')

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
        console.error('method:', key, 'args:', data)
        ack({
          status: 'error',
          error: `${err}`,
        })
      }
    }
  }

  handleError(message) {
    console.error('error message from frida'.red)
    console.error((message.stack || message).red)
  }

  async getAgent(name) {
    const prefix = path.join(__dirname, '..', 'agent', `${name}.bundle`)
    const source = await readFile(`${prefix}.js`, 'utf8')
    return this.session.createScript(source)
  }
}

class BannerStream extends Writable {
  constructor(opt) {
    super(opt)
    this.socket = opt.socket
  }

  _write(chunk, encoding, callback) {
    this.socket.write(chunk, callback)
  }
}

class RpcHandler extends Handler {
  constructor(session, socket) {
    super()

    this.session = session
    this.socket = socket
    this.stream = createSocketStream(socket)
    this.cache = new Cache()
    this.transfer = new Map()
    this.userScripts = new Map()
    this.syslogServer = null
    this.syslogClients = new Set()
    this.syslogFile = path.join(os.tmpdir(), Math.random().toString(16).slice(2))
  }

  async createSysLogServer() {
    const server = net.createServer((client) => {
      const ip = client.address().address.green
      this.syslogClients.add(client)
      console.log(`new client ${ip}`)
      const writable = new BannerStream({ socket: client })
      fs.createReadStream(this.syslogFile).on('error', () => {}).pipe(writable)
      client.on('end', () => {
        console.log(`client ${ip} disconnected`)
        this.syslogClients.delete(client)
      })
    })
    this.syslogServer = server
    return new Promise((resolve, reject) => {
      server.listen({ host: 'localhost', port: 0 }, () => {
        const serverPort = server.address().port
        console.log(`nc localhost ${serverPort}`.yellow)
        resolve(serverPort)
      }).on('error', reject)
    })
  }

  async load() {
    const { socket } = this
    const script = await this.getAgent('app')
    script.destroyed.connect(() => {
      socket.emit('script_destroyed')
      socket.disconnect(true)
      this.syslogClients.forEach(client => client.end('process has been terminated'.gray))
      this.syslogServer.close()
    })
    script.message.connect((message, data) => {
      const mapping = {
        send: this.handleSend,
        error: this.handleError,
      }
      const handler = mapping[message.type]
      if (typeof handler === 'function')
        handler.call(this, message, data)
      else
        console.warn(`unhandled message type: ${message.type}`.yellow)
    })

    await script.load()
    this.script = script
    this.agent = script.exports

    this.handleMessage()
    this.socket.emit('syslog-port', await this.createSysLogServer())
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
    } else if (payload.subject === 'syslog') {
      fs.appendFile(this.syslogFile, data, () => {})
      this.syslogClients.forEach(client => client.write(data))
    } else {
      if (data !== null) {
        console.warn('does not support binary protocol yet, message payload:'.yellow)
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

      'dumpKeyChain',
      'cookies',

      'hook',
      'unhook',
      'swizzle',
      'unswizzle',

      'dumpdecrypted',
      'screenshot',
    ].forEach(event => this.socket.on(event, this.wrap(event)))

    this.socket.use((packet, next) => {
      const [method, args, _] = packet
      // todo: middleware
      return next()
    })

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

    script.destroyed.connect(() => {
      socket.emit('userScript', {
        subject: 'destroyed',
        uuid,
      })
    })

    script.message.connect((message, data) => {
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
      const result = await script.exports.bootstrap(source)
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
    return this.cache.fetch('modules', () => this.agent.modules())
  }

  async exports({ module }) {
    return this.agent.exports(module)
  }

  async classes() {
    return this.cache.fetch('classes', () => this.agent.classes())
  }

  async ownClasses() {
    return this.cache.fetch('ownClasses', () => this.agent.ownClasses())
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
    if (data && data.name)
      return this.agent.imports(data.name)
    return []
  }

  async ls({ pathName, root }) {
    return this.agent.ls(pathName, root)
  }

  async plist(fileName) {
    return this.agent.plist(fileName)
  }

  async text(fileName) {
    return this.agent.text(fileName)
  }

  async tables(fileName) {
    return this.agent.tables(fileName)
  }

  async data(arg) {
    return this.agent.data(arg)
  }

  async download(fileName) {
    return this.agent.download(fileName)
  }

  async dumpWindow() {
    return this.agent.dumpWindow()
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

module.exports = {
  RpcHandler,
}
