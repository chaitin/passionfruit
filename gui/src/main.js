import Vue from 'vue'
import io from 'socket.io-client'
import Buefy from 'buefy'
import 'buefy/lib/buefy.css'
import axios from 'axios'

import App from '~/App.vue'
import router from '~/router'
import store from '~/vuex'
import { humanFileSize, hexAddr } from '~/lib/utils'

import RPC from '~/lib/wsrpc'

import 'material-design-icons/iconfont/material-icons.css'

import { LOAD_DEVICES } from '~/vuex/types'

//
require('promise.prototype.finally').shim()
axios.defaults.baseURL = '/api'


Vue.use(Buefy)
Vue.use(RPC)
Vue.filter('filesize', humanFileSize)
Vue.filter('hex', hexAddr)


const v = new Vue({
  el: '#app',
  router,
  store,
  render: h => h(App),
})

const socket = io('/devices', { path: '/msg' })
socket
  .on('deviceRemove', (dev) => {
    store.dispatch(LOAD_DEVICES)
    v.$toast.open(`${dev.name} has been removed`)
  })
  .on('deviceAdd', (dev) => {
    store.dispatch(LOAD_DEVICES)
    v.$toast.open(`New device ${dev.name}`)

    if (v.$route.name === 'welcome')
      v.$router.push({ name: 'apps', params: { device: dev.id }})
  })
  .on('warning', msg => v.$toast.open(msg))
