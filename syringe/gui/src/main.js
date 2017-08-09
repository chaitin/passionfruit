import Vue from 'vue'
import App from './App.vue'
import Buefy from 'buefy'

import 'buefy/lib/buefy.css'
import router from './router'

import "material-design-icons/iconfont/material-icons.css"

Vue.use(Buefy)

new Vue({
  el: '#app',
  router,
  render: h => h(App)
})
