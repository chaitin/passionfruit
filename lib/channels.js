const frida = require('frida')
const socketIO = require('socket.io')
const RpcHandler = require('./rpc')
const { serializeDevice, serializeApp, FridaUtil } = require('./utils')


const io = socketIO({ path: '/msg' })
const channels = {}

for (const namespace of ['devices', 'session', 'shell'])
  channels[namespace] = io.of(`/${namespace}`)

const deviceMgr = frida.getDeviceManager()
deviceMgr.events.listen('added', async device => channels.devices.emit('deviceAdd', serializeDevice(device)))
deviceMgr.events.listen('removed', async device => channels.devices.emit('deviceRemove', serializeDevice(device)))

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
    if (dev.type !== 'tether') throw new Error('device not found')

    socket.emit('device', serializeDevice(dev))
    const apps = await dev.enumerateApplications()
    app = apps.find(item => item.identifier === bundle)
    if (!app) throw new Error('app not installed')

    socket.emit('app', serializeApp(app))

    if (app.pid) {
      const front = await dev.getFrontmostApplication()
      if (front && front.pid === app.pid) {
        session = await dev.attach(app.name)
      } else {
        // if running background, restart it
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

  session.events.listen('detached', (reason) => {
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
  }).on('script', async({ source }, ack) => {
    try {
      const userScript = await session.createScript(source)
      try {
        await userScript.load()
        userScript.events.listen('message', (message) => {
          const { type, payload } = message
          if (type === 'send')
            socket.emit('send', payload)
          else if (type === 'error')
            socket.emit('error', payload)
        })
      } catch (ex) {
        ack({
          status: 'error',
          reason: 'failed to execute script',
          error: ex,
        })
        return
      }
    } catch (ex) {
      ack({
        status: 'error',
        reason: 'failed to compile script',
        error: ex,
      })
      return
    }
    ack({ status: 'ok' })
  })

  const rpcHandler = new RpcHandler(session, socket)
  await rpcHandler.load()
  socket.emit('ready')
})

exports.attach = server => io.attach(server)
