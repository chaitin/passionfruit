class KnownError extends Error {}

class DeviceNotFoundError extends KnownError {
  constructor(id) {
    super(`can not find device id: ${id}`)
  }
}

class DeviceNotReadyError extends KnownError {
  constructor() {
    super('you have to choose a device first')
  }
}

class ProcessNotFoundError extends KnownError {
  constructor(target) {
    super(`${target} is not running`)
  }
}

class AppNotFoundError extends KnownError {
  constructor(target) {
    super(`${target} not found in Applications`)
  }
}

class InvalidDeviceError extends KnownError {
  constructor(id) {
    super(`${id} is not an iOS device, or you have not installed frida on it`)
  }
}

class AppAttachError extends KnownError {
  constructor(bundle) {
    super(`unable to spawn app ${bundle}`)
  }
}

class CommandError extends KnownError {}

module.exports = {
  DeviceNotFoundError,
  DeviceNotReadyError,
  ProcessNotFoundError,
  AppNotFoundError,
  AppAttachError,
  InvalidDeviceError,
  KnownError,
  CommandError,
}
