import Vuex from 'vuex'
import Vue from 'vue'

import * as devices from './mods/devices'
// import modules from './mods/modules'


Vue.use(Vuex)


const store = new Vuex.Store({
  modules: {
    devices,
    // modules,
  }
})

export default store
