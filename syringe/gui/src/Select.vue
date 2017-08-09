<template>
  <div class="container">
    <div class="section">
      <div class="container">
        <b-dropdown v-model="device">
          <button class="button is-primary" type="button" slot="trigger">
            <template v-if="device">
              <h3><icon :icon="device.icon"></icon> {{ device.name }}</h3>
            </template>
            <template v-else>
              <h3><b-icon icon="important_devices"></b-icon>
                Please select a device</h3>              
            </template>
            <b-icon icon="arrow_drop_down"></b-icon>
          </button>

          <b-dropdown-item v-for="(dev, index) in devices" :value="dev" :key="dev.id">
            <div class="media">
              <div class="media-content">
                <h3><icon :icon="dev.icon"></icon> {{ dev.name }}</h3>
                <small>{{ dev.id }}</small>
              </div>
            </div>
          </b-dropdown-item>
        </b-dropdown>
      </div>
    </div>

    <div class="section">
      <b-table
        :data="apps"
        :loading="false"
        :hasDetails="false"
        default-sort="name">

        <template scope="props">
          <b-table-column field="largeIcon" width="64" label="">
            <icon :icon="props.row.largeIcon"></icon>
          </b-table-column>

          <b-table-column field="name" label="Name" sortable>
            {{ props.row.name }}
          </b-table-column>

          <b-table-column field="identifier" label="Bundle ID" sortable>
            {{ props.row.identifier }}
          </b-table-column>

          <b-table-column field="pid" label="PID" sortable>
            <
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
