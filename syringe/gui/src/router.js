import Vue from 'vue'
import VueRouter from 'vue-router'

import SelectView from './Select.vue'
import DeviceView from './Device.vue'

Vue.use(VueRouter)

const router = new VueRouter({
  mode: 'history',
  routes: [
    { path: '/select', component: SelectView, meta: { title: 'Select device and App' }, name: 'select' },
    { path: '/device/:device', component: DeviceView },
    { path: '/', redirect: '/select' }
  ]
})

router.beforeEach((to, from, next) => {
  document.title = to.meta.title || 'ipaspect'
  next()
})

export default router
