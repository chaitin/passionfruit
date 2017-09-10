const os = require('os')
const childProc = require('mz/child_process')
const frida = require('frida')
const plist = require('plist')

const { DeviceNotFoundError } = require('./error')


async function sleep(ms) {
  return new Promise((resolve, reject) => {
    setTimeout(resolve, ms)
  })
}


class FridaUtil {
  static async getDevice(id) {
    let list = await frida.enumerateDevices()
    let dev = list.find(dev => dev.id == id && dev.type == 'tether')

    if (dev)
      return dev

    throw new DeviceNotFoundError(id)
  }

  static async screenshot(id) {
    const tmp = os.tmpdir() + new Date().getTime() + '.png'
    return FridaUtil.getDevice(id).then(() => new Promise((resolve, reject) => {
      childProc.spawn('idevicescreenshot', ['-u', id, tmp])
        .on('close', code => {
          if (code == 0)
            resolve(tmp)
          else
            reject(code)
        })
        .on('error', reject)
    }))
  }

  // spawn and wait until it's ready
  static async spawn(dev, app) {
    let pid = await dev.spawn([app.identifier])
    let session = await dev.attach(pid)
    await dev.resume(pid)

    let probeScript = await session.createScript(
      `rpc.exports.ok = function() { return true }`)

    await probeScript.load()
    let probe = await probeScript.getExports()
    try {
      let ok = await retry(probe.ok.bind(probe))
      if (!ok)
        throw new Error(`failed to spawn or inject into ${app.identifier}`)
    } catch (ex) {
      console.error(ex)
      await session.detach()
      throw AppAttachError(bundle)
    }
    return session
  }

  static async info(id) {
    let [stdout, stderr] = await childProc.exec('ideviceinfo -x')
    return plist.parse(stdout)
  }
}

async function retry(operation, opt) {
  if (typeof operation != 'function')
    throw new Error('operation should be a function')

  opt = opt || {}
  let retry = opt.retry || 10
  let interval = opt.interval || 200
  while (--retry > 0) {
    try {
      return await operation()
    } catch (ignored) {
      console.log(ignored)
    }
    await sleep(interval)
  }

  throw new Error('max retry exceed')
}

function serializeIcon(icon) {
  let { pixels, height, width, rowstride } = icon
  pixels = pixels.toJSON()
  return { width, height, rowstride, pixels }
}

function serializeDevice(dev) {
  let { name, id, icon } = dev
  icon = serializeIcon(icon)
  return { name, id, icon }
}

function serializeApp(app) {
  let { name, id, smallIcon, largeIcon, identifier } = app
  smallIcon = serializeIcon(smallIcon)
  largeIcon = serializeIcon(largeIcon)
  return { name, id, smallIcon, largeIcon, identifier }
}


module.exports = {
  FridaUtil,
  serializeDevice,
  serializeApp,
  sleep,
  retry,
}