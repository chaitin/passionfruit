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

    <b-message v-if="err" type="is-danger" has-icon>{{ err }}</b-message>

    <div>
      <b-tabs position="is-centered" :expanded="true" :animated="false">
        <!-- todo: subview ? -->
        <b-tab-item label="Modules">
          <b-table
            class="modules"
            :data="modules"
            :narrowed="true"
            :hasDetails="false"
            :loading="loading.modules"
            :paginated="true"
            :per-page="20"
            default-sort="name">

            <template scope="props">
              <b-table-column field="name" label="Name" sortable>
                {{ props.row.name }}
              </b-table-column>

              <b-table-column field="baseAddress" label="Base" sortable>
                {{ props.row.baseAddress.value.toString(16) }}
              </b-table-column>

              <b-table-column field="size" label="Size" sortable>
                {{ props.row.size }}
              </b-table-column>

              <b-table-column field="path" label="Path">
                {{ props.row.path }}
              </b-table-column>
            </template>

            <div slot="empty" class="has-text-centered">
              Loading modules
            </div>
          </b-table>
        </b-tab-item>

        <b-tab-item label="General" v-if="app">

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
    app(val, old) {
      if (val.name)
        document.title = `ipaspect: ${val.name}`
    }
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

          // initialize
          this.loading.modules = true
          this.socket.emit('modules', {}, modules => {
            this.modules = modules
            this.loading.modules = false
          })

          // todo: checksec
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
      modules: [],

      loading: {
        modules: false,
      }
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

.modules {
  font-family: monospace;
  font-size: 14px;
}

</style>
