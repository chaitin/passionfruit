import Vue from 'vue'
import Buefy from 'buefy'
import 'buefy/lib/buefy.css'


import io from 'socket.io-client'
import App from './App.vue'
import router from './router'

import "material-design-icons/iconfont/material-icons.css"

Vue.use(Buefy)

new Vue({
  el: '#app',
  router,
  render: h => h(App)
})

// todo: vuex

const socket = io({ path: '/msg' })
socket.on('changed', console.log.bind(console))
socket.on('deviceChange', console.log.bind(console))
