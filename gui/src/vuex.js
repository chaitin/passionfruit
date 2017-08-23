import Vuex from 'vuex'
import Vue from 'vue'
import axios from 'axios'

require('promise.prototype.finally').shim()

axios.defaults.baseURL = '/api'

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
    deviceStatus: 'disconnected',
    loadingDevices: false,
    apps: [],
    app: {},
    appStatus: '',
    loadingApps: false,
    appsLoadErr: ''
  },
  getters: {
    device(state) { return state.devices.length ? state.device : {} },
    app(state) { return state.apps.length ? state.app : {} },
    ...directGetter('apps', 'devices', 'appsLoadErr', 'loadingApps', 'loadingDevices')
  },
  mutations: {
    removeDevice(state, device) {
      if (device.id == state.device.id) {
        state.app = []
        state.device = {}
        state.deviceStatus = 'disconnected'
      }
      // remove
      state.devices = state.devices.filter(dev => dev.id !== device.id)
    },
    setDevice(state, id) {
      let dev = state.devices.find(dev => dev.id == id)
      if (!dev) {
        state.appsLoadErr = 'device not found'
        state.deviceStatus = 'disconnected'
      } else {
        state.device = dev
        state.deviceStatus = 'connected'
      }
    },
    app(state, bundle) {
      state.app = bundle ?
        state.apps.find(app => app.identifier == bundle) : {}
    },
    addDevice(state, device) { state.devices.push(device) },
    ...directSetter('devices', 'apps', 'loadingApps', 'loadingDevices', 'appsLoadErr', 'deviceStatus'),
  },
  actions: {
    refreshDevices({ commit }) {
      commit('loadingDevices', true)
      axios.get('/devices')
        .then(({ data }) => {
          commit('loadingDevices', false)
          commit('devices', data)
        })
        .catch(err => {
          commit('loadingDevices', false)
          commit('devices', [])
          commit('device', {})
          // todo: handle error
        })
    },
    refreshApps({ commit, state }) {
      if (state.loadingDevices || !state.device || !state.device.id)
        return

      commit('loadingApps', true)
      commit('appsLoadErr', '')
      axios.get(`/device/${state.device.id}/apps/`)
        .then(({ data }) => {
          commit('loadingApps', false)
          commit('apps', data)
        })
        .catch(err => {
          commit('loadingApps', false)
          commit('apps', [])
          commit('appsLoadErr', err.response.data)
        })
    }
  }
})

export default store
