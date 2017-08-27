class DeviceNotFoundError extends Error {
  constructor(id) {
    super('can not find device id: ' + id)
  }
}

class DeviceNotReadyError extends Error {
  constructor() {
    super('you have to choose a device first')
  }
}

class ProcessNotFoundError extends Error {
  constructor(target) {
    super(target + ' is not running')
  }
}

class AppNotFoundError extends Error {
  constructor(target) {
    super(target + ' not found in Applications')
  }
}

class InvalidDeviceError extends Error {
  constructor(id) {
    super(`${id} is not an iOS device, or you have not installed frida on it`)
  }
}

module.exports = {
  DeviceNotFoundError,
  DeviceNotReadyError,
  ProcessNotFoundError,
  AppNotFoundError,
  InvalidDeviceError,
}