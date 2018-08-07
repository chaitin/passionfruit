const path = require('path')
const http = require('http')
const { Z_SYNC_FLUSH } = require('zlib')

require('colors')

const frida = require('frida')
const FRIDA_VERSION = require('frida/package.json').version
const Koa = require('koa')

const logger = require('koa-logger')
const json = require('koa-json')
const compress = require('koa-compress')
const bodyParser = require('koa-bodyparser')
const send = require('koa-send')
const Router = require('koa-router')

const { FridaUtil, serializeDevice, serializeApp } = require('./lib/utils')
const channels = require('./lib/channels.js')
const { KnownError, InvalidDeviceError, VersionMismatchError } = require('./lib/error')


const app = new Koa()
const router = new Router({ prefix: '/api' })

router
  .get('/devices', async (ctx) => {
    const list = await frida.enumerateDevices()
    ctx.body = {
      version: FRIDA_VERSION,
      list: list.filter(FridaUtil.isUSB).map(serializeDevice),
    }
  })
  .get('/device/:device/apps', async (ctx) => {
    const id = ctx.params.device
    // todo: refactor me
    try {
      const dev = await FridaUtil.getDevice(id)
      const apps = await dev.enumerateApplications()
      ctx.body = apps.map(serializeApp)
    } catch (ex) {
      if (ex.message.startsWith('Unable to connect to remote frida-server'))
        throw new InvalidDeviceError(id)
      if (ex.message.startsWith('Unable to communicate with remote frida-server'))
        throw new VersionMismatchError(ex.message)
      else
        throw ex
    }
  })
  .post('/device/spawn', async (ctx) => {
    const { device, bundle } = ctx.params
    const dev = await FridaUtil.getDevice(device)
    const pid = await dev.spawn([bundle])
    ctx.body = { status: 'ok', pid }
  })

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
      if (e instanceof KnownError) ctx.throw(404, e.message)

      if (process.env.NODE_ENV === 'development') throw e
      else ctx.throw(500, e.message)
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
    if (ctx.path.startsWith('/static/')) await send(ctx, ctx.path, opt)
    else await send(ctx, '/index.html', opt)

    next()
  })
  app.use(logger())
}

function start({ host, port }) {
  console.info(`listening on http://${host}:${port}`.green)
  const server = http.createServer(app.callback())
  channels.attach(server)
  server.listen(port, host)
  process.on('unhandledRejection', (err) => {
    console.error('An unhandledRejection occurred: '.red)
    console.error(`Rejection: ${err}`.red)
    console.error(err.stack)

    channels.broadcast('unhandledRejection', {
      err: err.toString(),
      stack: err.stack,
    })
  })
}

module.exports = {
  app,
  start,
}
