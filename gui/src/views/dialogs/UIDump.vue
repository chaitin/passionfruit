<template>
  <div>
    <b-modal :active.sync="active" width="100vw">
      <div class="modal-card">
        <header class="modal-card-head">
          <p class="modal-card-title">UIDump</p>
        </header>
        <section class="modal-card-body">
          <loading :radius="40" v-if="loading"></loading>
          <pre class="uidump" v-else>{{ description }}</pre>
        </section>
      </div>
    </b-modal>
  </div>
</template>

<script>
import { mapGetters } from "vuex";
import { GET_SOCKET } from '~/vuex/types'
import Loading from '~/components/Loading.vue';

export default {
  components: { Loading },
  props: {
    open: Boolean,
  },
  computed: {
    active: {
      set(val) {
        this.$emit('update:open', val)
      },
      get() {
        return this.open
      }
    },
    ...mapGetters({
      socket: GET_SOCKET,
    })
  },
  data() {
    return {
      loading: false,
      description: ''
    };
  },
methods: {
    refresh() {
      if (!this.socket || this.loading) return
      this.loading = true
      this.socket.call('dumpWindow')
        .then(description => this.description = description)
        // no need to catch, leave it to the global handler
        .finally(() => this.loading = false)
    },
  },
  watch: {
    open(val, old) {
      if (old === val)
        return
      
      if (val)
        this.refresh()
    }
  },
  mounted() {
    this.refresh()
  }
};
</script>

<style lang="scss" scoped>
pre.uidump {
  padding: 20px;
  overflow: auto;
}
</style>

