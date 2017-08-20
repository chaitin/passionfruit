const frida = require('frida')
const IO = require('koa-socket')

const FridaUtil = require('./frida_util')

const deviceMgr = frida.getDeviceManager()
const channels = {}

for (let channel of ['devices', 'session', 'shell']) {
  channels[channel] = new IO({ namespace: channel, ioOptions: { path: '/msg' } })
}

deviceMgr.events.listen('added', async device => {
  channels.devices.emit('deviceAdd', serializeDevice(device))
})

deviceMgr.events.listen('removed', async device => {
  channels.devices.emit('deviceRemove', serializeDevice(device))
})

channels.session.on('connection', async ({ socket }) => {
  let { device, bundle } = socket.handshake.query

  let dev = frida.getDevice(device)
  if (dev && dev.type == 'tether') {
    let session
    try {
      session = await device.attach(app)
    } catch (ex) {
      return socket.disconnect(ex.message)
    }
    session.events.on('detached', reason => {
      socket.emit('detached', reason)
      socket.disconnect('session detached')
    })
  } else {
    return socket.emit('devError', 'device not found')
  }

  socket.on('modules', async data => {
    let modules = await session.enumerateModules()
    socket.emit('modules', modules)
  }).on('spawn', async data => {

  }).on('attach', async data => {

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