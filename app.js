const path = require('path')
const os = require('os')
const fs = require('fs')
const childProc = require('mz/child_process')

const frida = require('frida')
const fridaLoad = require('frida-load')
const plist = require('plist')
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


const router = new Router({ prefix: '/api' })

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

function serializeDevice(dev) {
  let { name, id, icon } = dev
  icon.pixels = icon.pixels.toJSON()
  return { name, id, icon }
}

class FridaUtil {
  static async getDevice(id) {
    let list = await frida.enumerateDevices()
    let dev = list.find(dev => dev.id == id && dev.type == 'tether')

    if (dev)
      return dev

    throw new DeviceNotFoundError(id)
  }

  static screenshot(id) {
    const tmp = os.tmpdir() + new Date().getTime() + '.png'
    return new Promise((resolve, reject) => {
      // TODO: configurable executable path
      childProc.spawn('idevicescreenshot', ['-u', id, tmp]).on('close', code => {
        if (code == 0)
          resolve(tmp)
        else
          reject(code)
      })
    })
  }

  static async info(id) {
    let [stdout, stderr] = await childProc.exec('ideviceinfo -x')
    return plist.parse(stdout)
  }
}

io.on('connection', { socket } => {
  let device = null, session = null, injected = null

  // attach to process
  socket.on('attach', async data => {
    try {
      device = await FridaUtil.getDevice(data.device)
      // injected = await device.injectLibraryFile(data.app, libraryPath, 'entry', '')
      session = await device.attach(data.app)
    } catch(ex) {
      return socket.disconnect(ex.message)
    }
    session.events.listen('detached', reason =>
      socket.emit('detached', reason))
  }).on('spawn', data => {
    // todo: spawn process
  })
})

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
  .post('/device/spawn', async ctx => {
    let { device, bundle } = ctx.request.body

    let dev = await FridaUtil.getDevice(ctx.params.device)
    let pid = await dev.spawn([ctx.request.body.bundle])
    // todo: attach
    ctx.body = { status: 'ok'}
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
