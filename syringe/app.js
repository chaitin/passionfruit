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

class State {
  constructor() {
    this.device = null;
    this.session = null;
    this.target = null;
  }

  async initSession(target) {
    this.target = target
    this.session = await this.device.attach(target)
    this.session.enableJit()
    // this.session.events.listen('message', this.onMessage)
  }

  onMessage() {

  }
}

const state = new State()

router
  .get('/devices', async function(ctx) {
    const list = await frida.enumerateDevices()
    let usb = list.filter(dev => dev.type == 'tether')
    ctx.body = usb
  })
  .get('/apps/:device', async function(ctx) {
    const list = await frida.enumerateDevices()
    const dev = list.find(dev => dev.id.indexOf(ctx.params.device) == 0) // starts with

    if (dev) {
      const apps = await dev.enumerateApplications()
      ctx.body = apps
    } else {
      ctx.status = 400
      ctx.body = 'device not found'
      return
    }
  })
  .post('/select', async function(ctx) {
    const list = await frida.enumerateDevices()
    const dev = list.find(dev => dev.id.indexOf(ctx.request.body.device) == 0)

    if (dev) {
      state.device = dev
      ctx.body = { status: 'ok' }
    } else {
      ctx.status = 400
      ctx.body = 'device not found' // todo: middleware
      return
    }
  })
  .get('/appinfo', async function(ctx) {

  })
  .get('/screenshot', async function(ctx) {
    if (!state.device) {
      ctx.status = 404
      ctx.body = 'please select a device first'
      return
    }

    if (!state.session) {
      let app = await state.device.getFrontmostApplication()
      await state.initSession(app.pid)
    }

    let source = await fridaLoad(require.resolve('./agent/screenshot.js'))
    let script = await state.session.createScript(source)

    await script.load()
    let api = await script.getExports()
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
  .use(router.routes())
  .use(router.allowedMethods())
  .use(json({
    pretty: false,
    param: 'pretty'
  }))
  .listen(port)

console.info(`listening on http://localhost:${port}`)