const frida = require('frida')
const Koa = require('koa')
const IO = require('koa-socket')
const json = require('koa-json')
const compress = require('koa-compress')


const app = new Koa()
const io = new IO()

const router = require('koa-router')();

Buffer.prototype.toJSON = function() {
  return this.toString('base64')
}

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

io.attach(app)

app
  .use(compress({
    filter(contentType) {
      console.log('filter', contentType, /text|json/i.test(contentType))
      return /text|json/i.test(contentType)
    },
    threshold: 2048,
    flush: require('zlib').Z_SYNC_FLUSH
  }))
  .use(async function(ctx, next) {
    console.log(ctx, next)
    return await next()
  })
  .use(router.routes())
  .use(router.allowedMethods())
  .use(json({
    pretty: false,
    param: 'pretty'
  }))
  .listen(process.env.PORT || 31337)