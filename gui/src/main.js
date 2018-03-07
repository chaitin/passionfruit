import Vue from 'vue'
import io from 'socket.io-client'
import Buefy from 'buefy'
import 'buefy/lib/buefy.css'
import TreeView from 'vue-json-tree-view'
import axios from 'axios'

import App from '~/App.vue'
import router from '~/router'
import store from '~/vuex'
import { humanFileSize, hexAddr } from '~/lib/utils'


import 'material-design-icons/iconfont/material-icons.css'

import { ADD_DEVICE, REMOVE_DEVICE } from '~/vuex/types'

//
require('promise.prototype.finally').shim()
axios.defaults.baseURL = '/api'


Vue.use(TreeView)
Vue.use(Buefy)
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
    store.commit(REMOVE_DEVICE, dev)
    v.$toast.open(`${dev.name} has been removed`)
  })
  .on('deviceAdd', (dev) => {
    store.commit(ADD_DEVICE, dev)
    v.$toast.open(`New device ${dev.name} has been connected`)
  })
  .on('warning', msg => v.$toast.open(msg))
