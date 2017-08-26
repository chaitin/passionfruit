const os = require('os')
const childProc = require('mz/child_process')
const frida = require('frida')
const plist = require('plist')

const { DeviceNotFoundError } = require('./error')

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
      // TODO: configurable executable path
      childProc.spawn('idevicescreenshot', ['-u', id, tmp]).on('close', code => {
        if (code == 0)
          resolve(tmp)
        else
          reject(code)
      })
    }))
  }

  static async info(id) {
    let [stdout, stderr] = await childProc.exec('ideviceinfo -x')
    return plist.parse(stdout)
  }
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
}
