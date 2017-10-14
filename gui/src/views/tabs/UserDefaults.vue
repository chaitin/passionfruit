<template>
  <div>
    <plist :content="defaults" rootName="Root"></plist>
  </div>
</template>

<script>
import { mapGetters } from 'vuex'
import { GET_SOCKET } from '~/vuex/types'
import Plist from '~/components/Plist.vue'


export default {
  components: { Plist },
  data() {
    return {
      loading: false,
      defaults: {},
    }
  },
  mounted() {
    this.load()
  },
  methods: {
    async load() {
      this.loading = true
      try {
        this.defaults = await this.socket.call('userDefaults')
      } catch(e) {
        this.defaults = {}
        this.$toast.open({
          type: 'is-danger',
          text: 'failed to load user defaults',
        })
      } finally {
        this.loading = false
      }
    },
  },
  computed: {
    ...mapGetters({
      socket: GET_SOCKET,
    })
  },
}
</script>

<style>

</style>
