import Vue from 'vue'
import VueRouter from 'vue-router'

import WelcomeView from '~/views/Welcome.vue'
import DeviceView from '~/views/Device.vue'
import InspectView from '~/views/Inspect.vue'

import ModulesView from '~/views/tabs/Modules.vue'
import GeneralView from '~/views/tabs/General.vue'
import ClassesView from '~/views/tabs/Classes.vue'
import RangesView from '~/views/tabs/Ranges.vue'
import FinderView from '~/views/tabs/Finder.vue'


Vue.use(VueRouter)


const router = new VueRouter({
  mode: 'history',
  linkActiveClass: 'is-active',
  routes: [{
      path: '/',
      component: WelcomeView,
      meta: { title: 'Select an App to inspect' },
      name: 'welcome',
      children: [{
        path: 'apps/:device',
        component: DeviceView,
        name: 'apps'
      }]
    },
    {
      path: '/app/:device/:bundle',
      component: InspectView,
      name: 'inspect',
      children: [{
        path: 'general',
        component: GeneralView,
        name: 'general',
      }, {
        path: 'modules',
        component: ModulesView,
        name: 'modules',
      }, {
        path: 'classes',
        component: ClassesView,
        name: 'classes',
      }, {
        path: 'files',
        component: FinderView,
        name: 'files',
      }, {
        path: 'ranges',
        component: RangesView,
        name: 'ranges',
      }]
    }
  ]
})

router.beforeEach((to, from, next) => {
  document.title = to.meta.title || 'ipaspect'
  next()
})

export default router