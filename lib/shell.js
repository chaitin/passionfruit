const { spawn } = require('child_process')
const EventEmitter = require('events')

const net = require('net')
const ssh2 = require('ssh2')


const iproxyPool = new Map()


class IProxy extends EventEmitter {
  constructor(device) {
    if (typeof device !== 'string')
      throw new Error(`invalid device id: ${device}`)

    this.refCount = 1
    this.port = 0
    this.process = null
    this.session = null
    this.device = device
  }

  get connected() {
    return this.device && this.process && this.port
  }

  connect() {
    return new Promise((resolve, reject) => {
      let server = net.createServer(socket => {}).on('listening', () => {
        server.close()

        let port = this.port = server.address().port
        let proc = this.process = spawn(['iproxy', port.toString(), '22', this.device])

        if (!proc)
          reject(new Error('count not start iproxy'))

        proc.on('exit', (code, signal) => {
          this.process = null
          this.port = 0
          this.refCount = 0
          if (signal !== 'SIGTERM')
            this.emit('error', signal)
        }).on('error', reject)

      }).listen(0, '127.0.0.1')
    })
  }

  disconnect() {
    if (!this.connected)
      return

    this.emit('disconnect')
    this.session && this.session.end()
    subprocess.kill()
    this.emit('end')
  }
}


class SSH extends EventEmitter {
  static async connect(device) {
    if (typeof device !== 'string')
      throw Error('invalid device id: ${device}')

    let iproxy = iproxyPool.get(device)
    if (!iproxy) {
      iproxy = new IProxy(device)
      iproxyPool.set(device, iproxy)
      await iproxy.connect(device)
    }

    let ssh = new SSH(device)
    await ssh.connect()
    return ssh
  }

  constructor(device, iproxy) {
    this.device = device
    this.iproxy = iproxy
  }

  connect() {
    const ssh = new ssh2.Client()

    // todo: store password or private key in database
    return new Promise((resolve, reject) => {
      ssh.on('ready', () => {
        this.emit('ready')
        this.session = ssh
        resolve()
      }).on('error', err => {
        this.emit('error', err)
        reject(err)
      }).connect({
        host: '127.0.0.1',
        user: 'root',
        password: 'alpine',
        port: this.iproxy.port
      })
    })
  }

  exec(command) {
    return new Promise((resolve, reject) => {
      this.session.exec(command, (err, stream) => {
        if (err)
          reject(err)
        resolve(stream)
      })
    })
  }

  disconnect() {
    this.session.end()
    if (this.iproxy.refCount == 0) {
      this.iproxy.disconnect()
      iproxyPool.remove(this.iproxy)
    }
    this.emit('end')
  }
}


module.exports = {
  SSH,
  IProxy
}