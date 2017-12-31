<template>
  <div class="container">
    <section>
      <h1>
        <nav class="breadcrumb" aria-label="breadcrumbs">
          <ul>
            <li><a href="/"><b-icon icon="home"></b-icon><span>Passionfruit</span></a></li>
            <li class="is-active"><a>Url Launcher</a></li>
          </ul>
        </nav>
      </h1>
      <b-field>
        <b-select class="prefix" placeholder="Select a scheme" icon="home" tabindex="1" v-model="scheme">
          <optgroup label="Public">
            <option :value="url" v-for="(url, index) in schemes['public']"
              :key="index">{{ url }}://</option>
          </optgroup>
          <optgroup label="Private">
            <option :value="url" v-for="(url, index) in schemes['private']"
              :key="index">{{ url }}://</option>
          </optgroup>
        </b-select>
        <b-input placeholder="" expanded tabindex="2" v-model="url"
          @keyup.enter="open" :disabled="!connected"></b-input>
        <p class="control">
          <button class="button is-success" @click="open" :disabled="!connected">Start</button>
        </p>
      </b-field>

      <ul>
        <li v-for="(item, index) in history" :key="index">
          <a href="#" @click="start(item)">{{ item }}</a></li>
      </ul>

      <b-message title="Error" type="is-warning" v-show="err">
        {{ err }}            
      </b-message>
    </section>
  </div>
</template>

<script>
import io from 'socket.io-client'
import { mapGetters, mapMutations } from 'vuex'

import {
  GET_SOCKET, STORE_SOCKET,
} from '~/vuex/types'

export default {
  data() {
    return {
      schemes: {
        'private': [],
        'public': [],
      },
      history: [],
      scheme: '',
      url: '',
      device: '',
      loading: false,
      socket: null,

      connected: false,
      err: null,
    }
  },
  mounted() {
    const socket = this.socket = this.createSocket()
    this.storeSocket(socket)
    window.addEventListener('unhandledrejection', this.rejectionHandler)
  },
  beforeDestroy() {
    if (this.socket)
      this.socket.call('detach')
    window.removeEventListener('unhandledrejection', this.rejectionHandler)
  },
  methods: {
    ...mapMutations({
      storeSocket: STORE_SOCKET,
    }),
    rejectionHandler(event) {
      event.preventDefault()
      this.$toast.open({
        duration: 10 * 1000,
        message: event.reason,
        type: 'is-danger',
      })
    },
    createSocket() {
      let { device, scheme } = this.$route.params
      this.device = device
      this.loading = true

      if (scheme)
        this.scheme = scheme

      return io('/springboard', { path: '/msg', query: { device } })
        .on('disconnect', () => {
          this.$toast.open(`disconnected from ${device}`)
          this.err = 'Device disconnected. Reload the page to retry.'
          this.connected = false
          this.loading = false
        })
        .on('ready', () => {
          this.loading = false
          this.connected = true
          this.fetch()
        })
        .on('err', err => {
          this.err = err
          this.connected = false
          this.loading = false
        })
    },
    async fetch() {
      this.schemes = await this.socket.call('urls')
    },
    async open() {
      const url = [this.scheme, encodeURIComponent(this.url)].join('://')
      this.history.push(url)
      return this.start(url)
    },
    async start(url) {
      return this.socket.call('uiopen', url)
    },
  },
}
</script>

<style lang="scss" scoped>
h1 {
  margin-top: 100px;
}

.prefix {
  max-width: 240px;
}
</style>

