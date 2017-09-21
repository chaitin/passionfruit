const path = require('path')
const os = require('os')
const fs = require('fs')
const http = require('http')

const frida = require('frida')
const fridaLoad = require('frida-load')
const Koa = require('koa')

const logger = require('koa-logger')
const json = require('koa-json')
const compress = require('koa-compress')
const bodyParser = require('koa-bodyparser')
const Router = require('koa-router')

const { FridaUtil, serializeDevice } = require('./lib/utils')
const channels = require('./lib/channels.js')
const { KnownError } = require('./lib/error')


const app = new Koa()
const router = new Router({ prefix: '/api' })

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
    let id = ctx.params.device
    let dev = await FridaUtil.getDevice(id)
    try {
      ctx.body = await dev.enumerateApplications()
    } catch (ex) {
      if (ex.message.indexOf('Unable to connect to remote frida-server') === 0)
        throw new InvalidDeviceError(id)
      else
        throw ex
    }
  })
  .get('/device/:device/screenshot', async ctx => {
    let image = await FridaUtil.screenshot(ctx.params.device)
    ctx.body = fs.createReadStream(image)
    ctx.attachment(path.basename(image))
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
  .use(async(ctx, next) => {
    try {
      await next()
    } catch (e) {
      if (e instanceof KnownError) {
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
let server = http.createServer(app.callback())
channels.attach(server)
server.listen(port)


process.on('unhandledRejection', (err, p) => {
  console.error('An unhandledRejection occurred: ');
  console.error(`Rejection: ${err}`);
  console.error(err.stack)
})

module.exports = app