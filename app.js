const path = require('path')
const os = require('os')
const fs = require('fs')
const childProc = require('mz/child_process')

const frida = require('frida')
const fridaLoad = require('frida-load')
const plist = require('plist')
const Koa = require('koa')

const logger = require('koa-logger')
const json = require('koa-json')
const compress = require('koa-compress')
const bodyParser = require('koa-bodyparser')
const Router = require('koa-router')

const { FridaUtil, serializeDevice } = require('./lib/utils')
const io = require('./lib/channels.js')
const {
  DeviceNotFoundError,
  DeviceNotReadyError,
  ProcessNotFoundError,
  AppNotFoundError,
  InvalidDeviceError,
} = require('./lib/error')


const app = new Koa()
const router = new Router({ prefix: '/api' })

io.attach(app)

// hack: convert buffer to base64 string
Buffer.prototype.toJSON = function() {
  return this.toString('base64')
}

router
  .get('/devices', async ctx => {
    const list = await frida.enumerateDevices()
    ctx.body = list.filter(dev => dev.type == 'tether').map(serializeDevice)
  })
  .get('/device/:device/info', async ctx => {
    ctx.body = await FridaUtil.info(ctx.params.device)
  })
  .get('/device/:device/apps', async ctx => {
    let dev = await FridaUtil.getDevice(ctx.params.device)
    ctx.body = await dev.enumerateApplications()
  })
  .get('/device/:device/screenshot', async ctx => {
    let image = await FridaUtil.screenshot(ctx.params.device)
    ctx.body = fs.createReadStream(image)
    ctx.attachment(path.basename(image))
  })
  .get('/device/:device/env', async ctx => {
    // todo: query device command utils availability
  })
  .post('/device/:device/setup', async ctx => {
    // todo: install command utils on device
  })
  .post('/device/spawn', async ctx => {
    let { device, bundle } = ctx.request.body
    let dev = await FridaUtil.getDevice(ctx.params.device)
    let pid = await dev.spawn([ctx.request.body.bundle])
    ctx.body = { status: 'ok', pid }
  })

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
      if ([AppNotFoundError, DeviceNotFoundError, ProcessNotFoundError, InvalidDeviceError]
          .some(clz => e instanceof clz)) {
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
