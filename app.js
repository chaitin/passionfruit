const path = require('path')
const fs = require('fs')
const http = require('http')
const { Z_SYNC_FLUSH } = require('zlib')

const frida = require('frida')
const Koa = require('koa')

const logger = require('koa-logger')
const json = require('koa-json')
const compress = require('koa-compress')
const bodyParser = require('koa-bodyparser')
const send = require('koa-send')
const Router = require('koa-router')

const { FridaUtil, serializeDevice } = require('./lib/utils')
const channels = require('./lib/channels.js')
const { KnownError, InvalidDeviceError } = require('./lib/error')


const app = new Koa()
const router = new Router({ prefix: '/api' })

// hack: convert buffer to base64 string
/* eslint func-names:0 */
Buffer.prototype.toJSON = function() {
  return this.toString('base64')
}

router
  .get('/devices', async (ctx) => {
    const list = await frida.enumerateDevices()
    ctx.body = list.filter(dev => dev.type === 'tether').map(serializeDevice)
  })
  .get('/device/:device/info', async (ctx) => {
    ctx.body = await FridaUtil.info(ctx.params.device)
  })
  .get('/device/:device/apps', async (ctx) => {
    const id = ctx.params.device
    const dev = await FridaUtil.getDevice(id)
    try {
      ctx.body = await dev.enumerateApplications()
    } catch (ex) {
      if (ex.message.indexOf('Unable to connect to remote frida-server') === 0)
        throw new InvalidDeviceError(id)
      else
        throw ex
    }
  })
  .get('/device/:device/screenshot', async (ctx) => {
    const image = await FridaUtil.screenshot(ctx.params.device)
    ctx.body = fs.createReadStream(image)
    /* eslint prefer-template: 0 */
    ctx.attachment(path.basename(image) + '.png')
  })
  .post('/device/spawn', async (ctx) => {
    const { device, bundle } = ctx.params
    const dev = await FridaUtil.getDevice(device)
    const pid = await dev.spawn([bundle])
    ctx.body = { status: 'ok', pid }
  })

const port = parseInt(process.env.PORT, 10) || 31337
const host = process.env.HOST || 'localhost'


app
  .use(compress({
    filter(contentType) {
      return /text|json/i.test(contentType)
    },
    threshold: 2048,
    flush: Z_SYNC_FLUSH,
  }))
  .use(bodyParser())
  .use(async(ctx, next) => {
    try {
      await next()
    } catch (e) {
      if (e instanceof KnownError)
        ctx.throw(404, e.message)

      if (process.env.NODE_ENV === 'development')
        throw e
      else
        ctx.throw(500, e.message)
    }
  })
  .use(router.routes())
  .use(router.allowedMethods())


if (process.env.NODE_ENV === 'development') {
  app.use(json({
    pretty: false,
    param: 'pretty',
  }))
} else {
  app.use(async (ctx, next) => {
    const opt = { root: path.join(__dirname, 'gui') }
    if (ctx.path.startsWith('/dist/'))
      await send(ctx, ctx.path, opt)
    else // SPA
      await send(ctx, '/index.html', opt)

    next()
  })
  app.use(logger())
}

console.info(`listening on http://${host}:${port}`)
const server = http.createServer(app.callback())
channels.attach(server)
server.listen(port, host)


process.on('unhandledRejection', (err) => {
  console.error('An unhandledRejection occurred: ')
  console.error(`Rejection: ${err}`)
  console.error(err.stack)
})

module.exports = app
