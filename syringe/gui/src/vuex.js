import Vuex from 'vuex'
import Vue from 'vue'
import axios from 'axios'


Vue.use(Vuex)

const store = new Vuex.Store({
  state: {
    devices: [],
    device: {},
    app: {},
    apps: [],
  },
  getters: {
    device(state) { return state.devices.length ? state.device : {} },
    devices(state) { return state.devices },
    apps(state) { return state.apps },
    app(state) { return state.apps.length ? state.app : {} }
  },
  mutations: {
    addDevice(state, device) { state.devices.push(device) },
    removeDevice(state, device) {
      if (device.id == state.device.id) {
        state.app = []
        device = null
      }
      // remove
      state.devices = state.devices.filter(dev => dev.id !== device.id)
    },
    devices(state, list) { state.devices = list },
    device(state, id) { state.device = state.devices.find(dev => dev.id == id) },
    app(state, bundle) { state.app = state.apps.find(app => app.identifier == bundle) },
    apps(state, list) { state.apps = list}
  },
  actions: {
    refreshDevices({ commit }) {
      axios.get('/api/devices')
        .then(({ data }) => commit('devices', data))
    },
    refreshApps({ commit, state }) {
      axios.get('/api/apps/' + state.device.id)
        .then(({ data }) => commit('apps', data))
    }
  }
})

export default store
