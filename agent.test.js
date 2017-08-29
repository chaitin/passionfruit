const frida = require('frida')
const fridaLoad = require('frida-load')
const { sleep, FridaUtil } = require('./lib/utils')

async function main(methodName) {
  let dev = await frida.getUsbDevice()
  let apps = await dev.enumerateApplications()

  let targetApp = apps.find(app => app.pid == 0)
  if (!targetApp) {
    throw Error('failed to find a app to launch')
  }

  console.info(`spawn ${targetApp.identifier}`)

  let session = await FridaUtil.spawn(dev, targetApp)
  let source = await fridaLoad(require.resolve('./frida/index'))
  let script = await session.createScript(source)

  await script.load()
  let api = await script.getExports()
  let hr = '--'.repeat(10)

  let callMethod = async (name) => {
    try {
      console.log(hr, name, hr)
      let result = await api[name]()
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

  console.log(hr, 'detach', hr)
  await session.detach()
  console.log('kill process', session.pid)
  await dev.kill(session.pid)
  console.log('bye')
}

process.on('unhandledRejection', error => {
  console.error('unhandledRejection:')
  console.error(error)
})

main(process.argv[2] || 'info')
