import Vuex from 'vuex'
import Vue from 'vue'

import * as devices from './mods/devices'
import * as inspector from './mods/inspector'
import * as finder from './mods/finder'
import * as output from './mods/console'


Vue.use(Vuex)


const store = new Vuex.Store({
  modules: {
    devices,
    inspector,
    finder,
    output,
  }
})

export default store
