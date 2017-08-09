<template>
  <div>
    <b-dropdown v-model="device">
      <button class="button is-primary" type="button" slot="trigger">
        <template>
          <span>{{ deviceName }}</span>
        </template>
        <b-icon icon="arrow_drop_down"></b-icon>
      </button>

      <b-dropdown-item v-for="(dev, index) in devices" :value="dev">
        <div class="media">
          <div class="media-content">
            <h3><icon :icon="dev.icon"></icon> {{ dev.name }}</h3>
            <small>{{ dev.id }}</small>
          </div>
        </div>
      </b-dropdown-item>
    </b-dropdown>

    <b-table
      v-if="apps.length"
      :data="apps"
      :loading="false"
      :hasDetails="false"
      default-sort="app.identifier">

      <template scope="props">
        <b-table-column width="64">
          <icon :icon="props.row.largeIcon"></icon>
        </b-table-column>

        <b-table-column field="app.name" label="Name" sortable>
          {{ props.row.name }}
        </b-table-column>

        <b-table-column field="app.identifier" label="Bundle ID" sortable>
          {{ props.row.identifier }}
        </b-table-column>

        <b-table-column field="app.pid" label="PID" sortable>
          {{ props.row.pid }}
        </b-table-column>
    </template>

    <template slot="detail" scope="props">
      <article class="media">
        <figure class="media-left">
          <p class="image is-64x64"></p>
        </figure>
        <div class="media-content">
          <div class="content">
            <p></p>
          </div>
        </div>
      </article>
    </template>

    <div slot="empty" class="has-text-centered">
      Please select a device
    </div>
    </b-table>
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
    loadDevices() {
      axios.get('/api/devices').then(({ data }) => this.devices = data)
    },
    loadApps() {
      axios.get('/api/apps/' + this.device.id).then(({ data }) => this.apps = data)
    }
  },
  watch: {
    $route(to, from) {
      this.loadDevices()
    },
    device(to, from) {
      this.loadApps()
    }
  },
  data() {
    return {
      device: null,
      deviceName: 'Please select a device',
      devices: [],
      apps: [],
    }
  },
  mounted() {
    this.loadDevices()
  }
}
</script>

<style>

</style>
