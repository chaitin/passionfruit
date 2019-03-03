<template>
  <div>
    <b-modal :active.sync="active">
      <div class="viewport">
        <div class="preview">
          <a class="download" :href="url" :download="download" title="Right click to save">
            <img class="screenshot-preview" :src="url">
          </a>
        </div>

        <div class="toolbar">
          <span>Refresh rate</span>
          <b-field>
            <b-radio-button v-model="interval" native-value="-1">Don't</b-radio-button>
            <b-radio-button v-model="interval" native-value="1">Fast</b-radio-button>
            <b-radio-button v-model="interval" native-value="3">Medium</b-radio-button>
            <b-radio-button v-model="interval" native-value="10">Slow</b-radio-button>
          </b-field>
        </div>
      </div>
    </b-modal>
  </div>
</template>

<script>
import { mapGetters } from "vuex";
import { GET_SOCKET } from "~/vuex/types";

export default {
  props: {
    open: Boolean
  },
  computed: {
    active: {
      set(val) {
        this.$emit("update:open", val);
      },
      get() {
        return this.open;
      }
    },
    ...mapGetters({
      socket: GET_SOCKET
    })
  },
  data() {
    return {
      loading: false,
      interval: "-1",
      timer: -1,
      url:
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=",
      download: "screenshot.png"
    };
  },
  methods: {
    async refresh() {
      if (!this.socket || this.loading) return;
      const b64 = await this.socket.call("screenshot");
      this.url = `data:image/png;base64,${b64}`;
      this.download = `screenshot-${new Date().getTime()}.png`;
    },
    stop() {
      if (this.timer !== -1) {
        clearInterval(this.timer);
        this.timer = -1;
      }
    }
  },
  watch: {
    open(val, old) {
      if (old === val) return;

      if (val) this.refresh();
    },
    interval(val, old) {
      const interval = +val;
      this.stop()

      if (interval === -1) return;
      this.timer = setInterval(this.refresh, interval * 1000);
    }
  },
  mounted() {
    this.refresh();
  }
};
</script>

<style lang="scss" scoped>
.preview {
  text-align: center;

  .download {
    display: block;
  }
}

.viewport {
  position: relative;
  height: calc(100vh - 120px);
}

.toolbar {
  text-align: center;
  position: absolute;
  z-index: 2;
  bottom: 40px;
  left: 50%;
  transform: translateX(-50%);
  margin: auto;
  padding: 10px;
  color: white;
  border-radius: 4px;
}

img {
  max-height: calc(100vh - 60px);
  max-width: 100wh;
}
</style>

