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
      <b-tabs position="is-centered" :expanded="true" :animated="false">
        <b-tab-item label="General">
          <general-view></general-view>
        </b-tab-item>

        <b-tab-item label="Modules">
          <modules-view></modules-view>
        </b-tab-item>

        <b-tab-item label="Classes">
          <classes-view></classes-view>
        </b-tab-item>

        <b-tab-item label="Ranges">
          <ranges-view></ranges-view>
        </b-tab-item>
      </b-tabs>
    </div>
  </div>
</template>

<script>

import io from 'socket.io-client'
import { mapGetters, mapActions, mapMutations } from 'vuex'
import { AsyncSearch, debounce } from '~/lib/utils'
import { GET_SOCKET, STORE_SOCKET } from '~/vuex/types'

import Icon from '~/components/Icon.vue'

import ModulesView from '~/views/tabs/Modules.vue'
import GeneralView from '~/views/tabs/General.vue'
import ClassesView from '~/views/tabs/Classes.vue'
import RangesView from '~/views/tabs/Ranges.vue'

export default {
  components: {
    Icon,
    ModulesView,
    GeneralView,
    ClassesView,
    RangesView,
  },
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
          this.socket.emit('kill', {}, result => {
            if (result) {
              this.$toast.open(`${bundle} has been terminiated`)
            }
          })
        }
      })
    },
    createSocket() {
      let { device, bundle } = this.$route.params
      return io('/session', { path: '/msg' })
        .on('attached', console.info.bind(console))
        .on('close', console.warn.bind(console))
        .on('disconnect', () => {
          this.err = 'Application disconnected'
          this.connected = false
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
        .emit('attach', { device, bundle }, data => {
          if (data.status == 'error') {
            this.$toast.open(`failed to attach to ${bundle}`)
            this.err = data.message
            this.loading = false
          }
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
  },
  beforeDestroy() {
    if (this.socket)
      this.socket.emit('detach')
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
