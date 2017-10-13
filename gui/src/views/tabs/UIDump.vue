<template>
  <div>
    <b-field class="level-left">
      <button class="button" @click="refresh" :class="{ 'is-loading': loading }">
        <b-icon icon="refresh"></b-icon>
        <span>Refresh</span>
      </button>
      <button class="button" @click="toggleDebugOverlay">
        <b-icon icon="build"></b-icon>
        <span>Toggle Debug Information Overlay (iOS 10+)</span>
      </button>
    </b-field>

    <pre class="uidump">{{ description }}</pre>

    <p class="section is-size-7">
      <a target="_blank" href="https://revealapp.com/" class="has-text-info">Reveal</a> or even Xcode is much more powerful for view debugging.</p>
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
    },
    async toggleDebugOverlay() {
      await this.socket.call('toggleDebugOverlay')
      this.$toast.open(`Operation succeeded.
        Tap status bar with two fingers on device to toggle the window`)
    },
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
