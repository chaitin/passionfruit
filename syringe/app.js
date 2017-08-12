const path = require('path')
const os = require('os')
const spawn = require('mz/child_process').spawn

const frida = require('frida')
const fridaLoad = require('frida-load')
const Koa = require('koa')
const IO = require('koa-socket')
const logger = require('koa-logger')
const json = require('koa-json')
const compress = require('koa-compress')
const bodyParser = require('koa-bodyparser')
const Router = require('koa-router')

const app = new Koa()
const io = new IO({ioOptions: {path: '/msg'}})
const deviceMgr = frida.getDeviceManager()

// deviceMgr.events.listen('changed', async () => {
//   let devices = await state.devices()
//   io.broadcast('deviceChange')
// })
deviceMgr.events.listen('added', async device => {
  io.broadcast('deviceAdd', serializeDevice(device))
})
deviceMgr.events.listen('removed', async device => {
  io.broadcast('deviceRemove', serializeDevice(device))
})


const router = new Router({prefix: '/api'})

Buffer.prototype.toJSON = function() {
  return this.toString('base64')
}

class DeviceNotFoundError extends Error {
  constructor(id) {
    super('can not find device id: ' + id)
  }
}

class DeviceNotReadyError extends Error {
  constructor() {
    super('you have to choose a device first')
  }
}

class ProcessNotFoundError extends Error {
  constructor(target) {
    super(target + ' is not running')
  }
}

class AppNotFoundError extends Error {
  constructor(target) {
    super(target + ' not found in Applications')
  }
}

class InvalidDeviceError extends Error {
  constructor(id) {
    super(`${id} is not an iOS device`)
  }
}

// TODO: move to a module

const DEVICE = Symbol('device')
const SESSION = Symbol('device')
const TARGET = Symbol('target')
const SCRIPTS = Symbol('scripts')


function serializeDevice(dev) {
  let { name, id, icon } = dev
  icon.pixels = icon.pixels.toJSON()
  return { name, id, icon }
}

class State {
  constructor() {
    this[TARGET] = null
    this[DEVICE] = null
    this[SESSION] = null
  }

  async devices() {
    const list = await frida.enumerateDevices()
    return list.filter(dev => dev.type == 'tether')
  }

  async selectDevice(id) {
    const list = await this.devices()
    const dev = list.find(dev => dev.id.indexOf(id) == 0)
    if (!dev)
      throw new DeviceNotFoundError(id)

    let processes
    try {
      processes = await dev.enumerateProcesses()
    } catch(e) {
      console.error(e)
      throw new InvalidDeviceError(dev.id)
    }

    if (!processes.some(p => p.name == 'launchd')) {
      throw new InvalidDeviceError(dev.id)
    }

    // dev.events.listen('spawned', async spawn => {
    //   io.broadcast('spawned', await state.device.enumerateApplications())
    // })
    // dev.enableSpawnGating()
    this[DEVICE] = dev
  }

  get device() {
    if (this[DEVICE])
      return this[DEVICE]

    throw new DeviceNotReadyError()
  }

  async loadScript(filename) {
    let normalized = path.normalize(path.sep + filename)
    let fullPath = '.' + path.sep + path.join('agent', normalized)
    // TODO: cache script
    let source = await fridaLoad(require.resolve(fullPath))
    let session = await this.getSession()
    let script = await session.createScript(source)
    script.events.listen('message', (message, data) => {
      // todo
    })
    await script.load()
    return await script.getExports()
  }

  async getSession() {
    if (this[SESSION])
      return this[SESSION]

    let app = await this.device.getFrontmostApplication()
    if (!app)
      throw Error('no app running')

    return await this.startSession(app.pid)
  }

  async detachSession() {
    if (this[SESSION])
      await this[SESSION].detach()
  }

  async startSession(target) {
    // detach previous session
    this.detachSession()

    let session
    try {
      session = await this.device.attach(target)
    } catch (attachError) {
      if (attachError.message != 'Process not found')
        throw attachError

      if (typeof target !== 'string')
        throw new ProcessNotFoundError(target)

      try {
        let pid = await this.device.spawn([target])
        session = await this.device.attach(pid)
      } catch(spawnError) {
        throw new AppNotFoundError(target)
      }
    }
    session.enableJit()

    this[TARGET] = target
    this[SESSION] = session
    // session.events.listen
    return session
  }

  onMessage() {

  }
}

const state = new State()

router
  .get('/devices', async ctx => {
    let list = await state.devices()
    ctx.body = list.map(serializeDevice)
  })
  .get('/apps', async ctx => {
    ctx.body = await state.device.enumerateApplications()
  })
  .get('/apps/:device', async ctx => {
    await state.selectDevice(ctx.params.device)
    ctx.body = await state.device.enumerateApplications()
  })
  .post('/app', async ctx => {
    await state.startSession(ctx.request.body.app)
    ctx.body = { status: 'ok' }
  })
  .post('/device', async ctx => {
    await state.selectDevice(ctx.request.body.device)
    ctx.body = { status: 'ok' }
  })
  .post('/spawn', async ctx => {
    let pid = await state.device.spawn([ctx.request.body.bundle])
    // todo: attach
    ctx.body = { status: 'ok'}
  })
  .get('/script', async ctx => {
    let script = ctx.request.body.script

    let api = await state.loadScript('info')
    ctx.body = await api.main()
  })
  .get('/detach', async ctx => {
    await state.detachSession()
    ctx.body = { status: 'ok' }
  })
  .get('/screenshot', async ctx => {
    const filename = os.tmpdir() + new Date().getTime() + '.png'
    letspawn('idevicescreenshot', ['-u', '', filename])
    // todo: use idevicescreenshot
    ctx.throw(501, 'to be implemented')
  })

io.attach(app)

const port = process.env.PORT || 31337

app
  .use(compress({
    filter(contentType) {
      return /text|json/i.test(contentType)
    },
    threshold: 2048,
    flush: require('zlib').Z_SYNC_FLUSH
  }))
  .use(bodyParser())
  .use(async (ctx, next) => {
    try {
      await next()
    } catch (e) {
      if ([AppNotFoundError, DeviceNotFoundError, ProcessNotFoundError, InvalidDeviceError].some(clz => e instanceof clz)) {
        ctx.throw(404, e.message)
      }

      if (process.env.NODE_ENV == 'development') {
        throw e
      } else {
        ctx.throw(500, e.message)
      }
    }
  })
  .use(router.routes())
  .use(router.allowedMethods())

if (process.env.NODE_ENV == 'development') {
  app.use(json({
    pretty: false,
    param: 'pretty'
  }))

} else {
  app.use(logger())
}

console.info(`listening on http://localhost:${port}`)
app.listen(port)

module.exports = app
