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
    // todo: module and types
    devices: [],

    device: {},
    loadingDeviceDetail: false,
    deviceDetailErr: '',
    deviceDetail: {},

    apps: [],
    loadingApps: false,
    appsLoadErr: '',

    app: {},
  },
  getters: {
    device(state) { return state.devices.length ? state.device : {} },
    app(state) { return state.apps.length ? state.app : {} },
    ...directGetter('apps', 'devices', 'appsLoadErr', 'loadingApps', 'loadingDevices',
      'deviceDetail', 'loadingDeviceDetail')
  },
  mutations: {
    addDevice(state, device) { state.devices.push(device) },
    removeDevice(state, device) {
      if (device.id == state.device.id) {
        state.app = []
        state.device = {}
        state.appsLoadErr = 'device is disconnected'
      }
      state.devices = state.devices.filter(dev => dev.id !== device.id)
    },
    setDevice(state, id) {
      let dev = state.devices.find(dev => dev.id == id)
      if (!dev) {
        state.appsLoadErr = 'device not found'
      } else {
        state.appsLoadErr = ''
        state.device = dev
      }
    },
    app(state, bundle) {
      state.app = bundle ?
        state.apps.find(app => app.identifier == bundle) : {}
    },
    ...directSetter('devices', 'apps', 'loadingApps', 'loadingDevices',
      'appsLoadErr', 'loadingDeviceDetail'),
  },
  actions: {
    loadDevices({ commit, state }) {
      commit('devices', [])
      axios.get('/devices')
        .then(({ data }) => commit('devices', data))
    },
    loadDeviceDetail({ commit, state }) {
      if (!state.device.id)
        return

      commit('loadingDeviceDetail', true)
      axios.get(`/device/${state.device.id}/info`)
        .then(({ data }) => state.deviceDetail = data)
        .catch(err => state.deviceDetail = {})
        .finally(() => commit('loadingDeviceDetail', false))
    },
    refreshApps({ commit, state }) {
      if (!state.device.id)
        return

      commit('loadingApps', true)
      commit('appsLoadErr', '')
      axios.get(`/device/${state.device.id}/apps/`)
        .then(({ data }) => commit('apps', data))
        .catch(err => {
          commit('apps', [])
          commit('appsLoadErr', err.response.data)
        })
        .finally(() => commit('loadingApps', false))
    }
  }
})

export default store
