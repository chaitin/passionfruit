<template>
  <div class="container is-fluid">
    <header>
      <nav class="breadcrumb nav-bar" aria-label="breadcrumbs">
        <ul>
          <li><a href="/">ipaspect</a></li>
          <li><router-link v-if="device" :to="{ name: 'apps', params: { device: device.id }}">
            <icon :icon="device.icon"></icon> {{ device.name }}</router-link></li>
          <li class="is-active"><a href="#" aria-current="page">
            <icon :icon="app.smallIcon"></icon> {{ app.name }}</a>
            <div class="tags has-addons">
              <span class="tag is-light">{{ app.identifier }}</span>
              <span class="tag is-success" v-if="app.pid">pid: {{ app.pid }}</span>
            </div>
          </li>
        </ul>
      </nav>
    </header>

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

import { mapGetters, mapActions, mapMutations } from 'vuex'
import Icon from '~/components/Icon.vue'

export default {
  components: {
    Icon,
  },
  watch: {
    devices(val, old) {
      // detect device removal
      if (this.device.id != this.$route.params.device)
        this.$router.push({name: 'welcome'})
    },
  },
  methods: {

  },
  data() {

  },
  mounted() {
    // todo: connect
    
  },
  beforeDestroy() {
    // todo: disconnect
  },
  computed: {
    ...mapGetters({
      device: 'device',
      devices: 'devices',
    })
  }
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
