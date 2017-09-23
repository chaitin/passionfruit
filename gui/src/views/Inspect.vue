<template>
  <div class="container is-fluid">
    <header class="level is-marginless">
      <nav class="breadcrumb nav-bar level-left" aria-label="breadcrumbs">
        <ul class="level-item">
          <li>
            <a href="/">ipaspect</a>
          </li>
          <li v-if="err">Unknown device</li>
          <li v-else>
            <router-link v-if="device.id" :to="{name: 'apps', params: {device: device.id}}">
              <icon :icon="device.icon"></icon> {{ device.name }}</router-link>
          </li>
          <li v-if="err">Unknown App</li>
          <li v-else class="is-active">
            <a href="#" v-if="app" aria-current="page">
              <icon :icon="app.smallIcon"></icon> {{ app.name }}</a>
            <div class="tags has-addons">
              <span class="tag is-light">{{ app.identifier }}</span>
              <span class="tag is-success" v-if="app.pid">pid: {{ app.pid }}</span>
            </div>
          </li>
        </ul>
      </nav>

      <div class="level-right">
        <nav class="level-item">
          <b-tooltip label="Screenshot" position="is-left">
            <a class="button is-light" :href="'/api/device/' + device.id + '/screenshot'" target="_blank">
              <b-icon icon="camera"></b-icon>
            </a>
          </b-tooltip>
          <b-tooltip label="Kill Process" position="is-left">
            <button class="button is-danger" @click="kill">
              <b-icon icon="exit_to_app"></b-icon>
            </button>
          </b-tooltip>
        </nav>
      </div>
    </header>

    <b-message v-if="err" type="is-danger" has-icon>{{ err }}</b-message>
    <b-loading :active="loading" :canCancel="true" @cancel="home"></b-loading>

    <div v-if="connected">
      <nav class="tabs is-centered is-fullwidth">
        <ul>
          <li><router-link :to="{ name: 'general' }">General</router-link></li>
          <li><router-link :to="{ name: 'files' }">Files</router-link></li>
          <li><router-link :to="{ name: 'modules' }">Modules</router-link></li>
          <li><router-link :to="{ name: 'classes' }">Classes</router-link></li>
          <li><router-link :to="{ name: 'ranges' }">Ranges</router-link></li>
        </ul>
      </nav>

      <section class="tab-content"><router-view class="tab-item"></router-view></section>
    </div>
  </div>
</template>

<script>

import io from 'socket.io-client'
import { mapGetters, mapActions, mapMutations } from 'vuex'
import { AsyncSearch, debounce } from '~/lib/utils'
import { GET_SOCKET, STORE_SOCKET } from '~/vuex/types'

import Icon from '~/components/Icon.vue'

export default {
  components: { Icon },
  watch: {
    // todo: detect device removal
    app(val, old) {
      if (val.name)
        document.title = `ipaspect: ${val.name}`
    },
  },
  computed: {
    ...mapGetters({
      socket: GET_SOCKET,
    })
  },
  methods: {
    home() {
      this.$route.push({ name: 'welcome' })
    },
    kill() {
      this.$dialog.confirm({
        title: 'Kill App',
        message: 'Are you sure you want to <b>kill</b> the process? The session will end.',
        confirmText: 'Kill',
        type: 'is-danger',
        hasIcon: true,
        onConfirm: () => {
          this.$router.push({ name: 'apps', params: this.$route.params })
          this.socket.call('kill').then(result => {
            if (result) {
              this.$toast.open(`${bundle} has been terminiated`)
            }
          })
        }
      })
    },
    createSocket() {
      let { device, bundle } = this.$route.params
      return io('/session', { path: '/msg', query: { device, bundle } })
        .on('attached', console.info.bind(console))
        .on('close', console.warn.bind(console))
        .on('disconnect', () => {
          this.$toast.open(`failed to connect to ${bundle}`)
          this.err = 'Application disconnected'
          this.connected = false
          this.loading = false
        })
        .on('device', dev => this.device = dev)
        .on('app', app => this.app = app)
        .on('ready', () => {
          this.loading = false
          this.connected = true
        })
        .on('err', err => {
          this.err = err
          this.loading = false
        })
    },
    rejectionHandler(event) {
      event.preventDefault()
      this.$toast.open({
        duration: 10 * 1000,
        message: event.reason,
        type: 'is-danger',
      })
    },
    ...mapMutations({
      storeSocket: STORE_SOCKET,
    })
  },
  data() {
    return {
      err: '',
      loading: true,
      connected: false,
      app: {},
      device: {},
    }
  },
  mounted() {
    const socket = this.createSocket()
    this.storeSocket(socket)
    window.addEventListener('unhandledrejection', this.rejectionHandler)
  },
  beforeDestroy() {
    if (this.socket)
      this.socket.call('detach')
    window.removeEventListener('unhandledrejection', this.rejectionHandler)
  },
}
</script>

<style lang="scss" scoped>
.breadcrumb {
  margin: 10px 0;

  canvas {
    margin-right: 4px;
  }
}

.monospace {
  font-family: monospace;
}

.break-all {
  word-break: break-all;
}

.search {
  margin-top: 0;
}

</style>
