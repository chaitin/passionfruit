<template>
  <div>
    <b-modal :active.sync="active">
      <loading :radius="40" v-if="loading"></loading>
      <div class="preview" v-else>
        <a :href="url" :download="download" title="Right click to save">
          <img class="screenshot-preview" :src="url"></a>
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
      url: 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=',
      download: 'screenshot.png',
    };
  },
  methods: {
    async refresh() {
      if (!this.socket || this.loading) return;

      this.loading = true;
      const b64 = await this.socket.call("screenshot");
      this.loading = false

      this.url = `data:image/png;base64,${b64}`;
      this.download = `screenshot-${new Date().getTime()}.png`;
    }
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
.preview {
  text-align: center;
}

img {
  max-height: calc(100vh - 60px);
  max-width: 100wh;
}
</style>

