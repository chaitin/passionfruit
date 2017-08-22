const frida = require('frida')
const IO = require('koa-socket')

const { serializeDevice, FridaUtil } = require('./utils')

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

channels.session.on('connection', async ({ socket }) => {
  let { device, bundle } = socket.handshake.query

  let dev, session
  try {
    dev = await frida.getDevice(device)
    if (dev.type != 'tether')
      throw new Error('device not found')

    session = await device.attach(bundle)
  } catch(ex) {
    return socket.disconnect(ex.message)
  }

  session.events.on('detached', reason => {
    socket.emit('detached', reason)
    socket.disconnect('session detached')
  })
  socket.emit('attached', session.pid)

  socket.on('modules', async data => {
    let modules = await session.enumerateModules()
    socket.emit('modules', modules)
  }).on('detach', async data => {
    // todo: spawn
  }).on('checksec', async data => {

  }).on('ranges', async ({ protection }) => {
    let ranges = await session.enumerateRanges(protection)
    socket.emit('ranges', ranges)
  }).on('exports', async ({ module }) => {
    let symbols = session.enumerateExports(module)
    socket.emit('exports', symbols)
  }).on('classes', async () => {
    // todo: agent.exports
  }).on('methods', async ({ clz }) => {
    // todo: agent.exports.classes
  }).on('addHook', async ({ clz, method }) => {

  }).on('unhook', async ({ id }) => {
    // todo:
  })
})

// channels.shell.on('connection', )

exports.attach = app => {
  for (let namespace of Object.values(channels)) {
    namespace.attach(app)
  }
}