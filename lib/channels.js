const frida = require('frida')
const fridaLoad = require('frida-load')
const IO = require('koa-socket')
const Cache = require('./cache')

const { serializeDevice, serializeApp, retry, FridaUtil } = require('./utils')

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
  let dev, session, app, agent
  let cache = new Cache()

  if (!device || !bundle) {
    socket.emit('err', 'invalid parameters')
    socket.disconnect()
    return
  }

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

    if (app.pid) {
      let front = await dev.getFrontmostApplication()
      if (front && front.pid == app.pid) {
        session = await dev.attach(app.name)
      } else {
        // if running background, restart it
        await dev.kill(app.pid)
        session = await FridaUtil.spawn(dev, app)
      }
    } else {
      session = await FridaUtil.spawn(dev, app)
    }

    acknowledge({
      status: 'ok',
      pid: session.pid
    })
  } catch (ex) {
    acknowledge({ status: 'error', msg: ex })
    console.error(ex)
    return socket.disconnect()
  }

  session.events.listen('detached', reason => {
    socket.emit('detached', reason)
    socket.disconnect()
  })

  // todo: remove koa-socket
  // totally a crap
  socket.socket.on('modules', async(data, ack) => {
    let modules = await session.enumerateModules()
    ack(modules)
  }).on('detach', async data => {
    socket.disconnect()
  }).on('kill', async(data, ack) => {
    let pid = session.pid
    await session.detach()
    await dev.kill(pid)
    ack(true)
    socket.disconnect()
  }).on('checksec', async data => {

  }).on('ranges', async({ protection }, ack) => {
    // todo: decorator
    let ranges = await session.enumerateRanges(protection)
    ack(ranges)
  }).on('exports', async({ module }, ack) => {
    // todo: cache somewhere
    let symbols = await session.enumerateExports(module)
    ack(symbols)
  }).on('hook', async({ clz, method }, ack) => {

  }).on('unhook', async({ id }, ack) => {
    // todo:
  }).on('disconnect', async() => {
    await session.detach()
  }).on('script', async({ source }, ack) => {
    try {
      let userScript = await session.createScript(source)
      try {
        // note: user script does not support message events now
        await script.load()
      } catch (ex) {
        ack(`failed to run user script: ${ex}`)
      }
    } catch (ex) {
      ack(`failed to compile user script: ${ex}`)
    }
  }).on('message', (arg0, arg1, arg2) => {
    console.info('on message')
  })

  // load agent
  let source = await fridaLoad(require.resolve('../frida'))
  let script = await session.createScript(source)
  await script.load()
  script.events.listen('destroyed', () => {
    socket.emit('script_destroyed')
    socket.disconnect()
  })
  script.events.listen('message', (message, data) => {
    // todo: log and persistence
  })
  // todo: handle message
  agent = await script.getExports()
  socket.socket
    .on('classes', async({ needle }, ack) => {
      // needle: search keyword
      let classes = await cache.fetch('classes', agent.classes.bind(agent))
      ack(classes)
    }).on('methods', async({ clz }, ack) => {
      let methods = await cache.fetch(`methods_${clz}`, agent.methods.bind(agent, clz))
      ack(methods)
    }).on('info', async(data, ack) => {
      try {
        let result = await retry(async() => {
          let sec = await agent.checksec()
          let info = await agent.info()
          return { sec, info }
        })
        ack(result)
      } catch (ex) {
        console.error(ex)
        ack({})
      }
    }).on('lsof', async(data, ack) => {
      let files = await agent.lsof()
      ack(files)
    }).on('imports', async(data, ack) => {
      let name = (data && data.name) ? data.name : null
      let imports = await agent.imports()
      ack(imports)
    }).on('ls', async(path, ack) => {
      let result = path ? await agent.ls(path) : await agent.home()
      ack(result)
    })
    .emit('ready')
})

exports.attach = app => {
  for (let namespace of Object.values(channels)) {
    namespace.attach(app)
  }
}