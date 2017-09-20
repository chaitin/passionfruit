import * as types from '~/vuex/types'


export const state = {
  socket: null,
}


export const getters = {
  [types.GET_SOCKET]: state => state.socket,
}


export const mutations = {
  [types.STORE_SOCKET]: (state, socket) => state.socket = socket,
}

