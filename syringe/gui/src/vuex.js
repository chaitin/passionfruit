import Vuex from 'vuex'
import Vue from 'vue'
import axios from 'axios'


Vue.use(Vuex)

const store = new Vuex.Store({
  state: {
    devices: [],
    device: null,
    app: null,
    apps: [],
  },
  mutations: {
    devices(state, list) {
      state.devices = list
    },
    addDevice(state, device) {
      state.devices.push(device)
    },
    removeDevice(state, device) {
      if (device.id == state.device.id) {
        state.app = []
        device = null
      }

      // remove
      state.devices = state.devices.filter(dev => dev.id !== device.id)
    },
    switchDevice(state, device) {
      state.device = device
    },
    selectApp(state, app) {
      state.app = app
    }
  },
  actions: {
    refreshDevices({ commit }) {
      axios.get('/api/devices')
        .then(({ data }) => commit('devices', data))
    },
    refreshApps({ commit, state }) {
      axios.get('/api/apps/' + state.device.id)
        .then(({ data }) => commit('apps', this.apps))
    }
  }
})

export default store
