const frida = require('frida')
const socketIO = require('socket.io')
const { RpcHandler } = require('./rpc')
const { serializeDevice, serializeApp, FridaUtil } = require('./utils')


const io = socketIO({ path: '/msg' })
const channels = {}

for (const namespace of ['devices', 'session'])
  channels[namespace] = io.of(`/${namespace}`)

const deviceMgr = frida.getDeviceManager()
deviceMgr.added.connect(async device => channels.devices.emit('deviceAdd', serializeDevice(device)))
deviceMgr.removed.connect(async device => channels.devices.emit('deviceRemove', serializeDevice(device)))

channels.session.on('connection', async(socket) => {
  const { device, bundle } = socket.handshake.query

  let dev, session, app

  if (!device || !bundle) {
    socket.emit('err', 'invalid parameters')
    socket.disconnect(true)
    return
  }

  try {
    dev = await frida.getDevice(device)
    const apps = await dev.enumerateApplications()
    app = apps.find(item => item.identifier === bundle)
    if (!app) throw new Error('app not installed')

    socket.emit('app', {
      device: serializeDevice(dev),
      app: serializeApp(app),
    })

    if (app.pid) {
      const front = await dev.getFrontmostApplication()
      if (front && front.pid === app.pid) {
        session = await dev.attach(app.name)
      } else {
        await dev.kill(app.pid)
        session = await FridaUtil.spawn(dev, app)
      }
    } else {
      session = await FridaUtil.spawn(dev, app)
    }
  } catch (ex) {
    socket.emit('error', ex)
    console.error(ex)
    socket.disconnect(true)
    return
  }

  await session.enableJit()

  session.detached.connect((reason) => {
    socket.emit('detached', reason)
    socket.disconnect(true)
  })

  socket.on('detach', async() => {
    socket.disconnect()
  }).on('kill', async(data, ack) => {
    const { pid } = session
    await session.detach()
    await dev.kill(pid)
    ack(true)
    socket.disconnect()
  }).on('disconnect', async() => {
    await session.detach()
  })

  const handler = new RpcHandler(session, socket)
  await handler.load()
  socket.emit('ready')
})

exports.attach = server => io.attach(server)
exports.broadcast = channels.session.emit.bind(channels.session)
