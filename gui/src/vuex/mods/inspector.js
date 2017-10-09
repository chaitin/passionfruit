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
    (clazz, method) => // todo: one more lambda
    state.objc.hasOwnProperty(clazz) && state.objc[clazz][method],
  [types.IS_SYMBOL_HOOKED]: state =>
    (module, symbol) =>
    state.dylib.hasOwnProperty(module) && state.dylib[module][symbol],
}


export const actions = {
  [types.HOOK_DYLIB]: async({ state, commit }, opt) => {
    let { module, symbol, ret, args } = opt
    await state.socket.call('hook', opt)
    commit(types.HOOK_DYLIB, { module, symbol })
  },
  [types.HOOK_OBJC]: async({ state, commit }, { clazz, method }) => {
    if (state.objc[clazz] && state.objc[clazz][method])
      return
  },
}

export const mutations = {
  [types.HOOK_OBJC](state, { clazz, method }) {
    if (state.objc.hasOwnProperty(clazz))
      state.objc[clazz][method] = true
    else
      state.objc[clazz] = { method: true }
  },
  [types.UNHOOK_OBJC](state, { clazz, method }) {
    if (state.objc.hasOwnProperty(clazz))
      delete state.objc[clazz][method]
  },
  [types.HOOK_DYLIB](state, { module, symbol }) {
    if (state.dylib.hasOwnProperty(module))
      state.dylib[module][symbol] = true
    else
      state.dylib[module] = { symbol: true }
  },
  [types.UNHOOK_DYLIB](state, { module, symbol }) {
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