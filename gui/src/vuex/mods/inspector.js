import * as types from '~/vuex/types'


export const state = {
  socket: null,

  // hooks
  objc: {},
  dylib: {},
}


export const getters = {
  [types.GET_SOCKET]: state => state.socket,
  [types.IS_OBJC_HOOKED]: state =>
    (clz, method) => // todo: one more lambda
    state.objc.hasOwnProperty(clz) && state.objc[clz][method],
  [types.IS_SYMBOL_HOOKED]: state =>
    (module, symbol) =>
    state.dylib.hasOwnProperty(module) && state.dylib[module][symbol],
}


export const mutations = {
  [types.HOOK_OBJC](clz, method) {
    if (state.objc.hasOwnProperty(clz)) {
      state.objc[clz][method] = true
    } else {
      state.objc[clz] = { method: true }
    }
  },
  [types.UNHOOK_OBJC](clz, method) {
    if (state.objc.hasOwnProperty(clz))
      delete state.objc[clz][method]
  },
  [types.HOOK_DYLIB](module, symbol) {
    if (state.dylib.hasOwnProperty(module)) {
      state.dylib[module][symbol] = true
    } else {
      state.dylib[module] = { symbol: true }
    }
  },
  [types.UNHOOK_DYLIB](module, symbol) {
    if (state.dylib.hasOwnProperty(module))
      delete state.dylib[module][symbol]
  },
  [types.STORE_SOCKET](state, socket) {
    socket.call = (function(event, data) {
      return new Promise((resolve, reject) => {
        let ok = false
        this.emit(event, data, response => {
          if (response.status === 'ok') {
            ok = true
            resolve(response.data)
          } else {
            reject(response.error)
          }
        })

        setTimeout(() => {
          if (!ok)
            reject('Request timed out')
        }, 5000)
      })
    }).bind(socket)
    state.socket = socket
  },
}