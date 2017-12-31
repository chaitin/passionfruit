import Vue from 'vue'
import VueRouter from 'vue-router'

const WelcomeView = () => import(/* webpackChunkName: "first" */'~/views/Welcome.vue')
const DeviceView = () => import(/* webpackChunkName: "first" */'~/views/Device.vue')
const InspectView = () => import(/* webpackChunkName: "first" */'~/views/Inspect.vue')
const SubNavView = () => import(/* webpackChunkName: "first" */'~/views/SubNavigation.vue')
const URLTestView = () => import(/* webpackChunkName: "first" */'~/views/URLTest.vue')

const GeneralView = () => import(/* webpackChunkName: "first" */'~/views/tabs/General.vue')
const ModulesView = () => import(/* webpackChunkName: "first" */'~/views/tabs/Modules.vue')
const ClassesView = () => import(/* webpackChunkName: "first" */'~/views/tabs/Classes.vue')
const FinderView = () => import('~/views/tabs/Finder.vue')
const UIDumpView = () => import('~/views/tabs/UIDump.vue')
const ConsoleView = () => import('~/views/tabs/Console.vue')
const KeyChainView = () => import('~/views/tabs/KeyChain.vue')
const BinaryCookieView = () => import('~/views/tabs/BinaryCookie.vue')
const UserDefaultsView = () => import('~/views/tabs/UserDefaults.vue')


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
      path: '/url/:device/',
      component: URLTestView,
    },
    {
      path: '/url/:device/:scheme',
      component: URLTestView,
      name: 'uiopen',
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
        path: 'storage',
        component: SubNavView,
        name: 'storage',
        children: [
          {
            path: 'keychain',
            component: KeyChainView,
            name: 'keychain',
          },
          {
            path: 'cookies',
            component: BinaryCookieView,
            name: 'cookies',
          },
          {
            path: 'userdefaults',
            component: UserDefaultsView,
            name: 'userdefaults',
          }
        ]
      }, {
        path: 'uidump',
        component: UIDumpView,
        name: 'uidump',
      }]
    }
  ]
})

router.beforeEach((to, from, next) => {
  document.title = to.meta.title || 'Passionfruit'
  next()
})

export default router