import Vue from 'vue'
import Vuex from 'vuex'
import io from 'socket.io-client'
import Buefy from 'buefy'
import 'buefy/lib/buefy.css'


import App from '~/App.vue'
import router from '~/router'
import store from '~/vuex'

import "material-design-icons/iconfont/material-icons.css"

Vue.use(Buefy)

const v = new Vue({
  el: '#app',
  router,
  store,
  render: h => h(App)
})

// todo: vuex

const socket = io({ path: '/msg' })
socket
  .on('deviceChange', console.log.bind(console))
  .on('deviceRemove', dev => {
    store.commit('removeDevice', dev)
    v.$toast.open(`${dev.name} has been removed`)
  })
  .on('deviceAdd', dev => {
    store.commit('addDevice', dev)
    v.$toast.open(`New device ${dev.name} has been connected`)
  })
