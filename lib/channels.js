const frida = require('frida')
const IO = require('koa-socket')

const {
  serializeDevice,
  serializeApp,
  FridaUtil
} = require('./utils')

const deviceMgr = frida.getDeviceManager()
const channels = {}

for (let channel of ['devices', 'session', 'shell']) {
  channels[channel] = new IO({ namespace: '/' + channel, ioOptions: { path: '/msg' } })
}

deviceMgr.events.listen('added', async device => {
  channels.devices.broadcast('deviceAdd', serializeDevice(device))
})

deviceMgr.events.listen('removed', async device => {
  channels.devices.broadcast('deviceRemove', serializeDevice(device))
})

channels.session.on('attach', async(ctx, { device, bundle }) => {
  console.log('connect to', device, bundle)

  let { socket, acknowledge } = ctx
  let dev, session, app

  if (!device || !bundle)
    return socket.emit('err', 'invalid parameters').disconnect()

  try {
    dev = await frida.getDevice(device)
    if (dev.type != 'tether')
      throw new Error('device not found')

    socket.emit('device', serializeDevice(dev))
    let apps = await dev.enumerateApplications()
    app = apps.find(app => app.identifier == bundle)
    if (!app)
      throw new Error('app not installed')

    socket.emit('app', serializeApp(app))
    session = await dev.attach(app.name)
    acknowledge({
      status: 'ok',
      pid: session.pid
    })
  } catch(ex) {
    acknowledge({status: 'error', msg: ex})
    console.error(ex)
    return socket.disconnect()
  }

  session.events.listen('detached', reason =>
    socket.emit('detached', reason).disconnect())

  // todo: remove koa-socket
  // totally a crap
  socket.socket.on('modules', async (data, ack) => {
    let modules = await session.enumerateModules()
    ack(modules)
  }).on('detach', async data => {
    socket.disconnect()
  }).on('checksec', async data => {

  }).on('ranges', async ({ protection }, ack) => {
    let ranges = await session.enumerateRanges(protection)
    ack(ranges)
  }).on('exports', async ({ module }, ack) => {
    // todo: cache somewhere
    let symbols = await session.enumerateExports(module)
    ack(symbols)
  }).on('classes', async (data, ack) => {
    // todo: agent.exports
  }).on('methods', async ({ clz }, ack) => {
    // todo: agent.exports.classes
  }).on('addHook', async ({ clz, method }, ack) => {

  }).on('unhook', async ({ id }, ack) => {
    // todo:
  }).on('disconnect', async() => {
    await session.detach()
  })
})

exports.attach = app => {
  for (let namespace of Object.values(channels)) {
    namespace.attach(app)
  }
}