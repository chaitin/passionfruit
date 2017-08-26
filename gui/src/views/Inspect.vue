<template>
  <div class="container is-fluid">
    <header>
      <nav class="breadcrumb nav-bar" aria-label="breadcrumbs">
        <ul>
          <li><a href="/">ipaspect</a></li>
          <li><router-link v-if="device.id" :to="{name: 'apps', params: {device: device.id}}">
            <icon :icon="device.icon"></icon> {{ device.name }}</router-link></li>
          <li class="is-active"><a href="#" v-if="app" aria-current="page">
            <icon :icon="app.smallIcon"></icon> {{ app.name }}</a>
            <div class="tags has-addons">
              <span class="tag is-light">{{ app.identifier }}</span>
              <span class="tag is-success" v-if="app.pid">pid: {{ app.pid }}</span>
            </div>
          </li>
        </ul>
      </nav>
    </header>

    <b-message type="is-danger" has-icon>{{ err }}</b-message>

    <div>
      <b-tabs position="is-centered" :expanded="true" :animated="false">
        <b-tab-item label="General" v-if="app">

        </b-tab-item>

        <b-tab-item label="Modules">

        </b-tab-item>

        <b-tab-item label="Screenshots">

        </b-tab-item>
      </b-tabs>
    </div>
  </div>
</template>

<script>

import io from 'socket.io-client'
import { mapGetters, mapActions, mapMutations } from 'vuex'
import Icon from '~/components/Icon.vue'

export default {
  components: {
    Icon,
  },
  watch: {
    // todo: detect device removal
  },
  methods: {
    createSocket() {
      let { device, bundle } = this.$route.params
      return io('/session', { path: '/msg' })
        .on('attached', console.info.bind(console))
        .on('close', console.warn.bind(console))
        .on('disconnect', data => {
          this.err = 'Application connection is closed'
        })
        .on('device', dev => this.device = dev)
        .on('app', app => this.app = app)
        .emit('attach', { device, bundle }, data => {
          if (data.status == 'error') {
            this.$toast.open(`failed to attach to ${bundle}`)
            this.err = data.message
          }
        })
    }
  },
  data() {
    const socket = this.createSocket()

    return {
      err: '',
      app: {},
      socket,
      device: {},
    }
  },
  beforeDestroy() {
    this.socket.emit('detach')
  },
}
</script>

<style lang="scss" scoped>
.breadcrumb {
  margin: 10px auto;

  canvas {
    margin-right: 4px;
  }
}

</style>
