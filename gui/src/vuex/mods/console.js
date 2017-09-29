import * as types from '~/vuex/types'

const LIMIT = 1000

export const state = {
  list: [],
  unread: 0,
  active: false,
}

export const mutations = {
  [types.CONSOLE_APPEND](state, item) {
    state.list.unshift(item)
    if (state.list.length > LIMIT)
      state.list.pop()

    if (!state.active)
      state.unread++
  },
  [types.CONSOLE_ACTIVE](state, active) {
    state.active = active
    if (active) {
      state.unread = 0
    }
  }
}

export const getters = {
  [types.CONSOLE_LIST]: state => state.list,
  [types.CONSOLE_UNREAD]: state => state.unread,
}