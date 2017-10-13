import * as types from '~/vuex/types'


export const state = {
  socket: null,

  // hooks
  objc: {},
  dylib: {},
  hooks: [],
}


export const getters = {
  [types.GET_SOCKET]: state => state.socket,
  [types.IS_OBJC_HOOKED]: state =>
    (clazz, method) => // todo: one more lambda
    state.objc.hasOwnProperty(clazz) && state.objc[clazz][method],
  [types.IS_SYMBOL_HOOKED]: state =>
    (module, name) =>
    state.dylib.hasOwnProperty(module) && state.dylib[module][name],
  [types.ALL_HOOKS]: state => state.hooks,
}


export const actions = {
  [types.HOOK_DYLIB]: async({ state, commit }, opt) => {
    const { module, name } = opt
    if (state.dylib[module] && state.dylib[module][name])
      return

    await state.socket.call('hook', opt)
    commit(types.HOOK_DYLIB, opt)
  },
  [types.HOOK_OBJC]: async({ state, commit }, opt) => {
    const { clazz, method } = opt
    if (state.objc[clazz] && state.objc[clazz][method])
      return

    await state.socket.call('swizzle', opt)
    commit(types.HOOK_OBJC, opt)
  },
  [types.UNHOOK_OBJC]: async({ state, commit }, opt) => {
    await state.socket.call('unswizzle', opt)
    commit(types.UNHOOK_OBJC, opt)
  },
  [types.DELETE_HOOK]: async({ state, commit, dispatch }, index) => {
    const item = state.hooks[index]
    if (item.type === 'dylib') {
      await state.socket.call('unhook', item)
      commit(types.UNHOOK_DYLIB, item)
    } else if (item.type === 'objc') {
      dispatch(types.UNHOOK_OBJC, item)
    } else {
      throw new Error('unknown type' + item.type)
    }
    // todo: toast
  }
}

export const mutations = {
  [types.HOOK_OBJC](state, { clazz, method }) {
    const item = { type: 'objc', clazz, method }
    if (state.objc.hasOwnProperty(clazz))
      state.objc[clazz][method] = item
    else
      state.objc[clazz] = { method: item }
    state.hooks.push(item)
  },
  [types.UNHOOK_OBJC](state, { clazz, method }) {
    const item = state.objc[clazz][method]
    const index = state.hooks.indexOf(item)
    state.hooks.splice(index, 1)
    delete state.objc[clazz][method]
  },
  [types.HOOK_DYLIB](state, { module, name }) {
    const item = { type: 'dylib', module, name }
    if (state.dylib.hasOwnProperty(module))
      state.dylib[module][name] = item
    else
      state.dylib[module] = { name: item }
    state.hooks.push(item)
  },
  [types.UNHOOK_DYLIB](state, { module, name }) {
    const item = state.dylib[module][name]
    const index = state.hooks.indexOf(item)
    state.hooks.splice(index, 1)
    delete state.dylib[module][name]
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