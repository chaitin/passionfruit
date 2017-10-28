const os = require('os')
const { spawn } = require('child_process')
const frida = require('frida')
const plist = require('plist')

const { DeviceNotFoundError, CommandError, AppAttachError } = require('./error')


async function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms))
}


async function retry(operation, options) {
  if (typeof operation !== 'function')
    throw new Error('operation should be a function')

  const opt = options || {}
  let times = opt.retry || 10
  const interval = opt.interval || 200
  while (--times > 0) {
    try {
      return operation()
    } catch (ignored) {
      console.log(ignored)
    }
    await sleep(interval)
  }

  throw new Error('max retry exceed')
}


class FridaUtil {
  static async getDevice(id) {
    const list = await frida.enumerateDevices()
    const dev = list.find(d => d.id === id && d.type === 'tether')

    if (dev)
      return dev

    throw new DeviceNotFoundError(id)
  }

  static async screenshot(id) {
    const tmp = os.tmpdir() + new Date().getTime()
    return FridaUtil.getDevice(id).then(() => new Promise((resolve, reject) => {
      spawn('idevicescreenshot', ['-u', id, tmp])
        .on('close', (code) => {
          if (code === 0)
            resolve(tmp)
          else
            reject(code)
        })
        .on('error', reject)
    }))
  }

  // spawn and wait until it's ready
  static async spawn(dev, app) {
    const pid = await dev.spawn([app.identifier])
    const session = await dev.attach(pid)
    await dev.resume(pid)

    const probeScript = await session.createScript('rpc.exports.ok = function() { return true }')

    await probeScript.load()
    const probe = await probeScript.getExports()
    try {
      const ok = await retry(probe.ok.bind(probe))
      if (!ok)
        throw new AppAttachError(app.identifier)
    } catch (ex) {
      console.error(ex)
      await session.detach()
      throw new AppAttachError(app.identifier)
    }
    return session
  }

  static info(id) {
    return new Promise((resolve, reject) => {
      const child = spawn('ideviceinfo', ['-u', id, '-x'])
      const stdout = []
      child.stdout.on('data', data => stdout.push(data))
      child.on('close', (code) => {
        let message = stdout.join('')
        if (code !== 0) {
          if (message.match(/Could not connect to lockdownd, error code/)) {
            message = `Unable to connect to lockdownd, it may be a known issue.
              Try: sudo chmod -R 777 /var/db/lockdown/`
            console.error(message)
          }
          reject(new CommandError(message))
          return
        }
        resolve(plist.parse(message))
      })
    })
  }
}


function serializeIcon(icon) {
  if (!icon)
    return icon
  const { pixels, height, width, rowstride } = icon
  return { width, height, rowstride, pixels: pixels.toJSON() }
}

function serializeDevice(dev) {
  const { name, id, icon } = dev
  return { name, id, icon: serializeIcon(icon) }
}

function serializeApp(app) {
  const { name, id, smallIcon, largeIcon, identifier } = app
  return {
    name,
    id,
    identifier,
    smallIcon: serializeIcon(smallIcon),
    largeIcon: serializeIcon(largeIcon),
  }
}


module.exports = {
  FridaUtil,
  serializeDevice,
  serializeApp,
  sleep,
  retry,
}
