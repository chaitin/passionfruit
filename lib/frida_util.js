class FridaUtil {
  static async getDevice(id) {
    let list = await frida.enumerateDevices()
    let dev = list.find(dev => dev.id == id && dev.type == 'tether')

    if (dev)
      return dev

    throw new DeviceNotFoundError(id)
  }

  static screenshot(id) {
    const tmp = os.tmpdir() + new Date().getTime() + '.png'
    return new Promise((resolve, reject) => {
      // TODO: configurable executable path
      childProc.spawn('idevicescreenshot', ['-u', id, tmp]).on('close', code => {
        if (code == 0)
          resolve(tmp)
        else
          reject(code)
      })
    })
  }

  static async info(id) {
    let [stdout, stderr] = await childProc.exec('ideviceinfo -x')
    return plist.parse(stdout)
  }
}

module.exports = FridaUtil
