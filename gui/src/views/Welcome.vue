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
            <li v-if="!devices.length"><b-icon icon="error"></b-icon> No device found</li>
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
import { mapGetters, mapActions } from 'vuex'
import Icon from '~/components/Icon.vue'

export default {
  components: {
    Icon
  },
  computed: {
    ...mapGetters({
      devices: 'devices'
    })
  },
  methods: {
    ...mapActions({
      refresh: 'refreshDevices'
    })
  },
  watch: {
    $route(to, from) {
      this.refresh()
    },
  },
  mounted() {
    this.refresh()
  }
}
</script>

<style>

</style>
