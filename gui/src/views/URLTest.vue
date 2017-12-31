<template>
  <div class="container">
    <section>
      <h1>URL Launcher</h1>
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
        <b-input placeholder="" expanded tabindex="2" v-model="url"></b-input>
        <p class="control">
          <button class="button is-success" @click="open">Start</button>
        </p>
      </b-field>
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
      scheme: '',
      url: '',
      device: '',
      loading: false,
      socket: null,
    }
  },
  mounted() {
    const socket = this.socket = this.createSocket()
    this.storeSocket(socket)
  },
  beforeDestroy() {
    if (this.socket)
      this.socket.call('detach')
  },
  methods: {
    ...mapMutations({
      storeSocket: STORE_SOCKET,
    }),
    createSocket() {
      let { device } = this.$route.params
      this.device = device
      this.loading = true
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
          this.loading = false
        })
    },
    async fetch() {
      this.schemes = await this.socket.call('urls')
    },
    async open() {
      console.log(`${this.scheme}://${this.url}`)
      await this.socket.call('uiopen', `${this.scheme}://${this.url}`)
    }
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

