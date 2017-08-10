import Vue from 'vue'
import io from 'socket.io-client'
import Buefy from 'buefy'
import 'buefy/lib/buefy.css'


import App from './App.vue'
import router from './router'

import "material-design-icons/iconfont/material-icons.css"

Vue.use(Buefy)

const v = new Vue({
  el: '#app',
  router,
  render: h => h(App)
})

// todo: vuex

const socket = io({ path: '/msg' })
socket
  .on('deviceChange', console.log.bind(console))
  .on('deviceRemove', dev => {
    v.$toast.open(`${dev.name} has been removed`)

    // todo: if current device
  })
  .on('deviceAdd', dev => {
    v.$toast.open(`${dev.name} has been connected`)
  })
