<template>
  <div>
    <b-field>
      <button class="button" @click="refresh" :class="{ 'is-loading': loading }">
        <b-icon icon="refresh"></b-icon>
        <span>Refresh</span>
      </button>
    </b-field>
    <pre class="uidump">{{ description }}</pre>
  </div>
</template>

<script>
import { mapGetters } from 'vuex'
import LoadingTab from '~/components/LoadingTab.vue'
import { GET_SOCKET } from '~/vuex/types'


export default {
  computed: {
    ...mapGetters({
      socket: GET_SOCKET,
    })
  },
  data() {
    return {
      loading: false,
      description: ''
    }
  },
  methods: {
    refresh() {
      if (this.loading) return
      this.loading = true
      this.socket.call('dumpWindow')
        .then(description => this.description = description)
        // no need to catch, leave it to the global handler
        .finally(() => this.loading = false)
    }
  },
  mounted() {
    this.refresh()
  }
}
</script>

<style>
pre.uidump {
  padding: 20px;
  overflow: auto;
}
</style>
