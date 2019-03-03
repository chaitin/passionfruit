function install(Vue) {
  function notAllowed(target, key, receiver) {
    throw new Error(key + ' is readony')
  }

  const proxy = new Proxy({}, {
    get: function (target, key, receiver) {
      return function () {
        // todo:
      }
    },
    set: notAllowed,
    defineProperty: notAllowed,
    deleteProperty: notAllowed,
    preventExtensions: notAllowed,
    setPrototypeOf: notAllowed,
  })

  Object.defineProperty(Vue.prototype, '$rpc', {
    get() { return proxy }
  })
}

export default install

if (typeof window !== 'undefined' && window.Vue) {
  window.Vue.use(install)
  if (install.installed) {
    install.installed = false
  }
}