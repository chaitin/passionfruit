import Vue from 'vue'
import VueRouter from 'vue-router'

const WelcomeView = () => import(/* webpackChunkName: "first" */'~/views/Welcome.vue')
const DeviceView = () => import(/* webpackChunkName: "first" */'~/views/Device.vue')
const InspectView = () => import(/* webpackChunkName: "first" */'~/views/Inspect.vue')

const GeneralView = () => import(/* webpackChunkName: "first" */'~/views/tabs/General.vue')
const ModulesView = () => import('~/views/tabs/Modules.vue')
const ClassesView = () => import('~/views/tabs/Classes.vue')
const FinderView = () => import('~/views/tabs/Finder.vue')
const UIDumpView = () => import('~/views/tabs/UIDump.vue')
const KeyChainView = () => import('~/views/tabs/KeyChain.vue')
const ConsoleView = () => import('~/views/tabs/Console.vue')


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
        path: 'console',
        component: ConsoleView,
        name: 'console',
      }, {
        path: 'keychain',
        component: KeyChainView,
        name: 'keychain',
      }, {
        path: 'uidump',
        component: UIDumpView,
        name: 'uidump',
      }]
    }
  ]
})

router.beforeEach((to, from, next) => {
  document.title = to.meta.title || 'ipaspect'
  next()
})

export default router