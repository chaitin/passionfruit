import * as types from '~/vuex/types'

const LIMIT = 100

export const state = {
  list: [],
  unread: 0,
  active: false,
  logging: true,
  syslogServerPort: 0,
}

export const mutations = {
  [types.STORE_SYSLOG_SERVER_PORT](state, port) {
    state.syslogServerPort = port
  },
  [types.CONSOLE_RUNNING](state, on) {
    state.logging = on
  },
  [types.CONSOLE_APPEND](state, item) {
    if (!state.logging)
      return

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
  },
  [types.CONSOLE_CLEAR](state) {
    state.unread = 0
    state.list = []
  },
}

export const getters = {
  [types.CONSOLE_LIST]: state => state.list,
  [types.CONSOLE_UNREAD]: state => state.unread,
  [types.CONSOLE_RUNNING]: state => state.loggine,
  [types.GET_SYSLOG_SERVER_PORT]: state => state.syslogServerPort,
}