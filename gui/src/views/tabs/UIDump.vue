<template>
  <div>
    <b-field class="level-left">
      <p class="control">
        <button class="button" @click="refresh" :class="{ 'is-loading': loading }">
          <b-icon icon="refresh"></b-icon>
          <span>Refresh</span>
        </button>
      </p>

      <p class="control">
        <button class="button" @click="toggleDebugOverlay" ref="toggleDebug">
          <b-icon icon="build"></b-icon>
          <span>Debug Overlay (iOS 10+)</span>
        </button>
      </p>
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
      try {
        await this.socket.call('toggleDebugOverlay')
        this.$toast.open(
          `Operation succeeded. Tap status bar with two fingers
          on device to toggle the window`)
      } catch(e) {
        this.$toast.open({ message: e, type: 'is-danger' })
        this.$refs.toggleDebug.setAttribute('disabled', '')
      }
    },
  },
  mounted() {
    this.refresh()
  }
}
</script>

<style>
pre.uidump {
  padding: 10px;
  overflow: auto;
}
</style>
