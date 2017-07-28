const path = require('path')

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
const io = new IO()

const router = new Router({prefix: '/api'})

Buffer.prototype.toJSON = function() {
  return this.toString('base64')
}

class DeviceNotFoundError extends Error {}
class DeviceNotReadyError extends Error {}

const DEVICE = Symbol('device')
const SESSION = Symbol('device')
const TARGET = Symbol('target')
const SCRIPTS = Symbol('scripts')

class State {
  constructor() {
    this[TARGET] = null
    this[DEVICE] = null
    this[SESSION] = null
  }

  async selectDevice(id) {
    const list = await frida.enumerateDevices()
    const dev = list.find(dev => dev.id.indexOf(id) == 0)
    if (!dev)
      throw new DeviceNotFoundError('can not find device id: ' + id)

    this[DEVICE] = dev
  }

  get device() {
    if (this[DEVICE])
      return this[DEVICE]

    throw new DeviceNotReadyError()
  }

  async loadScript(filename) {
    let normalized = path.normalize(path.sep + filename)
    let fullPath = path.join('.', 'agent', normalized)
    let source = await fridaLoad(require.resolve(fullPath))
    let script = await state.session.createScript(source)
    await script.load(SCRIPTS)
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

  async startSession(target) {
    // detach previous session
    if (this[SESSION])
      this[SESSION].detach()

    let session = await this.device.attach(target)
    if (!session)
      throw Error('unable to find target: ' + target)

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
    const list = await frida.enumerateDevices()
    let usb = list.filter(dev => dev.type == 'tether')
    ctx.body = usb
  })
  .get('/apps', async ctx => {
    ctx.body = await this.device.enumerateApplications()
  })
  .post('/app', async ctx => {
    await state.startSession(ctx.request.body.app)
  })
  .post('/device', async ctx => {
    await state.selectDevice(ctx.request.body.device)
    ctx.body = {
      status: 'ok'
    }
  })
  .get('/appinfo', async ctx => {
    let api = await state.loadScript('info')
    let result = api.info()
    ctx.body = result
  })
  .get('/screenshot', async ctx => {
    let api = await loadScript('screenshot')
    let result = await api.screenshot()

    ctx.body = Buffer.from(result.png, 'base64')
    ctx.response.attachment('screenshot-' + new Date().getTime() + '.png')
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
  .use(logger())
  .use(async (ctx, next) => {
    try {
      await next()
    } catch (e) {
      if (e instanceof DeviceNotFoundError)
        ctx.throw(404, e.message || 'please select a device first')
      else
        ctx.throw(500, e.message || 'internal error')
    }
  })
  .use(router.routes())
  .use(router.allowedMethods())
  .use(json({
    pretty: false,
    param: 'pretty'
  }))
  .listen(port)

console.info(`listening on http://localhost:${port}`)

