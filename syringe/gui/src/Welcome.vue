<template>
  <div class="container is-fluid">
    <div class="columns section">
      <div class="column is-one-quarter">
        <h1 class="title has-text-grey-darker">ipaspect</h1>
        <aside class="menu">
          <p class="menu-label">
            Devices
          </p>
          <ul class="menu-list">
            <li v-for="dev in devices" :key="dev.id">
              <router-link :to="{ name: 'apps', params: { device: dev.id } }">
                <icon :icon="dev.icon"></icon> {{ dev.name }}
              </router-link>
            </li>
            <li v-if="!devices.length"><a>No device found</a></li>
          </ul>
          <p class="menu-label">
            General
          </p>
          <ul class="menu-list">
            <li><a>Preference</a></li>
            <li><a>Github</a></li>
          </ul>
        </aside>
      </div>

      <div class="column">
        <router-view></router-view>
      </div>

    </div>
  </div>

</template>

<script>
import axios from 'axios'
import Icon from './Icon.vue'

export default {
  components: {
    Icon
  },
  methods: {
    refresh() {
      axios.get('/api/devices').then(({ data }) => this.devices = data)
    },
  },
  watch: {
    $route(to, from) {
      this.refresh()
    },
    device(to, from) {
      this.loadApps()
    }
  },
  data() {
    return {
      devices: [],
    }
  },
  mounted() {
    this.refresh()
  }
}
</script>

<style>

</style>
