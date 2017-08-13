<template>
  <div class="container is-fluid">
    <div class="columns section">
      <div class="column is-one-quarter">
        <h1 class="title has-text-grey-darker"><router-link :to="'/welcome'">ipaspect</router-link></h1>
        <p class="menu-label">App</p>
        <article class="media">
          <figure class="media-left">
            <p class="image is-32x32">
              <icon :icon="app.largeIcon" v-if="app.largeIcon"></icon>
            </p>
          </figure>

          <div class="media-content">
            <div class="content">
              <h1>{{ app.name }}</h1>
              <p>{{ app.identifier }}</p>
            </div>
          </div>
        </article>
      </div>

      <div class="column">
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
  </div>

</template>

<script>

import { mapGetters, mapActions, mapMutations } from 'vuex'
import Icon from '~/components/Icon.vue'

export default {
  components: {
    Icon,
  },
  watch: {
    $route(to, from) {
      this.connect()
    },
    devices(to, from) {
      if (to.length) {
        this.setDevice(this.$route.params.device)
        this.refreshApps()
      }
    },
    apps(to, from) {
      if (to.length) {
        this.$store.commit('app', this.$route.params.bundle)
        // todo
      }
    }
  },
  mounted() {
    this.connect()
  },
  methods: {
    connect() {
      this.refreshDevices()
    },
    ...mapMutations({
      setDevice: 'setDevice',
    }),
    ...mapActions({
      refreshApps: 'refreshApps',
      refreshDevices: 'refreshDevices',
    })
  },
  computed: {
    ...mapGetters({
      device: 'device',
      devices: 'devices',
      app: 'app',
      apps: 'apps',
    })
  }
}
</script>

<style>

</style>
