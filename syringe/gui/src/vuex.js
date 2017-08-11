import Vuex from 'vuex'
import Vue from 'vue'
import axios from 'axios'


Vue.use(Vuex)

function directSetter(...keys) {
  const result = {}
  keys.forEach(key => {
    result[key] = (state, val) => {
      state[key] = val
    }
  })
  return result
}

function directGetter(...keys) {
  const result = {}
  keys.forEach(key => {
    result[key] = state => state[key]
  })
  return result
}

const store = new Vuex.Store({
  state: {
    devices: [],
    device: {},
    loadingDevices: false,
    apps: [],
    app: {},
    loadingApps: false,
    appLoadErr: ''
  },
  getters: {
    device(state) { return state.devices.length ? state.device : {} },
    app(state) { return state.apps.length ? state.app : {} },
    ...directGetter('apps', 'devices', 'appLoadErr')
  },
  mutations: {
    removeDevice(state, device) {
      if (device.id == state.device.id) {
        state.app = []
        device = null
      }
      // remove
      state.devices = state.devices.filter(dev => dev.id !== device.id)
    },
    device(state, id) { state.device = state.devices.find(dev => dev.id == id) },
    app(state, bundle) { state.app = state.apps.find(app => app.identifier == bundle) },
    addDevice(state, device) { state.devices.push(device) },

    ...directSetter('devices', 'apps', 'loadingApps', 'loadingDevices', 'appLoadErr'),

    // devices(state, list) { state.devices = list },
    // apps(state, list) { state.apps = list },
    // loadingApps(state, loading) { state.loadingApp = loading },
    // loadingDevices(state, loading) { state.loadingDevices = loading },
  },
  actions: {
    refreshDevices({ commit }) {
      commit('loadingDevices')
      axios.get('/api/devices')
        .then(({ data }) => {
          commit('devices', data)
        })
        .catch(err => {
          // todo: handle error
        })
    },
    refreshApps({ commit, state }) {
      commit('loadingApps', true)
      axios.get('/api/apps/' + state.device.id)
        .then(({ data }) => {
          commit('loadingApps', false)
          commit('apps', data)
        })
        .catch(err => {
          commit('loadingApps', false)
          commit('apps', [])
          commit('appLoadErr', err.response.data)
        })
    }
  }
})

export default store
