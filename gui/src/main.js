import Vue from 'vue'
import Vuex from 'vuex'
import io from 'socket.io-client'
import Buefy from 'buefy'
import 'buefy/lib/buefy.css'
import axios from 'axios'

//
require('promise.prototype.finally').shim()
axios.defaults.baseURL = '/api'


import App from '~/App.vue'
import router from '~/router'
import store from '~/vuex'
import { humanFileSize } from '~/lib/utils.js'


import "material-design-icons/iconfont/material-icons.css"

import { ADD_DEVICE, REMOVE_DEVICE } from '~/vuex/types'

Vue.use(Buefy)
Vue.filter('filesize', humanFileSize)


const v = new Vue({
  el: '#app',
  router,
  store,
  render: h => h(App)
})

const socket = io('/devices', { path: '/msg' })
socket
  .on('deviceRemove', dev => {
    store.commit(REMOVE_DEVICE, dev)
    v.$toast.open(`${dev.name} has been removed`)
  })
  .on('deviceAdd', dev => {
    store.commit(ADD_DEVICE, dev)
    v.$toast.open(`New device ${dev.name} has been connected`)
  })
  .on('warning', msg => v.$toast.open(msg))
