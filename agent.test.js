const frida = require('frida')
const fridaLoad = require('frida-load')
const { sleep, FridaUtil } = require('./lib/utils')

async function main(methodName, args) {
  let dev = await frida.getUsbDevice()
  let targetApp = await dev.getFrontmostApplication()
  let kill = false
  let session = null

  if (targetApp) {
    session = await dev.attach(targetApp.name)
  } else {
    console.info('no front most app, try spawn a new one')
    let apps = await dev.enumerateApplications()
    targetApp = apps.find(app => app.pid == 0)
    if (!targetApp) {
      throw Error('failed to find a app to launch')
    }
    kill = true
    session = await FridaUtil.spawn(dev, targetApp)
  }
  
  console.info(`attach to ${targetApp.identifier}`)

  let source = await fridaLoad(require.resolve('./frida/index'))
  let script = await session.createScript(source)

  script.events.listen('message', (message, data) => {
    console.log('on messsage')
    console.log(message)
    console.log(data)
  })

  await script.load()

  let api = await script.getExports()
  let hr = '--'.repeat(10)
  let parsedArgs = args.map(arg => {
    try {
      return JSON.parse(arg)
    } catch(e) {
      return arg + ''
    }
  })

  let callMethod = async (name) => {
    let method = api[name]
    if (!method)
      return console.error(`method ${name} unavaliable`)

    try {
      console.log(hr, name, hr)
      let result = await method.apply(null, parsedArgs)
      console.log(result)
    } catch(e) {
      console.error(`unable to execute script`)
      console.error(e)
    }
  }

  if (methodName) {
    await callMethod(methodName)
  } else {
    for (let key of Object.keys(api)) {
      await callMethod(key)
    }
  }

  // wait for 10s to handle messages
  await new Promise(resolve => setTimeout(resolve, 4 * 1000))
  console.log(hr, 'detach', hr)
  await session.detach()

  if (kill) {
    console.log('kill process', session.pid)
    await dev.kill(session.pid)
  }
  console.log('bye')
}

process.on('unhandledRejection', error => {
  console.error('unhandledRejection:')
  console.error(error)
})

main(process.argv[2] || 'info', process.argv.slice(3))
