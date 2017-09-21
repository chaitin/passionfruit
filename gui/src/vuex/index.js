import Vuex from 'vuex'
import Vue from 'vue'

import * as devices from './mods/devices'
import * as inspector from './mods/inspector'
import * as finder from './mods/finder'


Vue.use(Vuex)


const store = new Vuex.Store({
  modules: {
    devices,
    inspector,
    finder
  }
})

export default store
