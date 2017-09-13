import Vuex from 'vuex'
import Vue from 'vue'

import * as devices from './mods/devices'
import * as connection from './mods/connection'
// import modules from './mods/modules'


Vue.use(Vuex)


const store = new Vuex.Store({
  modules: {
    devices,
    connection,
    // modules,
  }
})

export default store
