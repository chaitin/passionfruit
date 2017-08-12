const frida = require('frida')
const fridaLoad = require('frida-load')


async function sleep(ms) {
  return new Promise((resolve, reject) => {
    setTimeout(resolve, ms)
  })
}

async function main(filename) {
  let dev = await frida.getUsbDevice()
  let apps = await dev.enumerateApplications()

  let targetApp = apps.find(app => app.pid == 0)
  if (!targetApp) {
    throw Error('failed to find a app to launch')
  }

  console.info(`spawn ${targetApp.identifier}`)

  let pid = await dev.spawn([targetApp.identifier])
  let session = await dev.attach(pid)
  console.info('app launching...')
  await dev.resume(pid)

  let probeScript = await session.createScript('rpc.exports.ok = function() { return true }')
  await probeScript.load()
  let probe = await probeScript.getExports()
  let retry = 10
  while(--retry > 0) {
    sleep(200)
    console.debug('retry:', retry)
    try {
      if (await probe.ok()) {
        console.debug('ok')
        break
      }
    } catch(ignored) {}
  }

  if (retry == 0) {
    console.error(`failed to spawn or inject into ${targetApp.identifier}`)
    return await session.detach()
  }

  let source = await fridaLoad(require.resolve('./agent/' + filename))
  let script = await session.createScript(source)

  await script.load()
  let api = await script.getExports()
  try {
    console.log(await api.main())
  } catch(e) {
    console.error(`unable execute script`)
    console.error(e)
  } finally {
    console.log('clean up')
    await dev.kill(pid)
    await session.detach()
  }
}

process.on('unhandledRejection', error => {
  console.error('unhandledRejection:')
  console.error(error)
})

main(process.argv[2] || 'info')
