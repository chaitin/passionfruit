<template>
  <div>
    <b-modal :active.sync="active" :width="1200">
      <section class="dialog section">
        <loading-tab v-if="loading"></loading-tab>
        <div v-else>
          <b-message type="is-danger" v-if="error">{{ error }}</b-message>
          <article class="content" v-if="content">
            <plist v-if="type == 'plist'" title="Plist Reader" :content="content" :rootName="file.name"></plist>
            <!-- TODO: component -->
            <div v-if="type == 'text'">
              <h2 class="title">TextViewer</h2>
              <pre class="hexdump">{{ hexdump }}</pre>
              <p class="is-size-7">File large than 1kb will be truncated</p>
            </div>
          </article>
        </div>
      </section>
    </b-modal>

  </div>
</template>

<script>
import { mapGetters } from 'vuex'
import { GET_SOCKET } from '~/vuex/types'
import LoadingTab from '~/components/LoadingTab.vue'
import Plist from '~/components/Plist.vue'

export default {
  components: { LoadingTab, Plist },
  props: {
    type: String,
    open: Boolean,
    file: Object,
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
    hexdump() {
      if (this.type != 'text')
        return

      let view = new DataView(this.content)
      let dump = '      0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F 0123456789ABCDEF'

      for (let i = 0; i < this.content.byteLength; i += 16) {
        dump += `\n${('0000' + i.toString(16).toUpperCase()).slice(-4)} `
        for (let j = 0; j < 16; j++) {
          let ch = i + j > this.content.byteLength - 1 ?
            '  ' :
            (0 + view.getUint8(i + j).toString(16).toUpperCase()).slice(-2)

          dump += `${ch} `
        }

        dump += String.fromCharCode.apply(null,
            new Uint8Array(this.content.slice(i, i + 16)))
          .replace(/[^\x20-\x7E]/g, '.')
      }

      return dump
    },
    ...mapGetters({
      socket: GET_SOCKET,
    })
  },
  data() {
    return {
      content: null,
      loading: false,
      error: null,
    }
  },
  watch: {
    open(val, old) {
      if (!old && val && this.file)
        this.view(this.file.path)
    },
    file(val, old) {
      if (val && this.open) {
        this.view(val.path)
      }
    }
  },
  mounted() {
    if (this.file && this.file.path)
      this.view(this.file.path)
  },
  methods: {
    view(path) {
      this.error = ''
      if (this.type === 'plist' || this.type == 'text') {
        this.loading = true
        this.socket.call(this.type, path).then(content => {
          this.content = content
          this.loading = false
        }).catch(err => {
          this.loading = false
          this.error = err
        })
      }
    }
  }
}
</script>

<style lang="scss">
pre.hexdump {

}

section.dialog {
  background: #fff;
}

.modal-content,
.modal-card {
  margin: 0 20px;
  max-height: calc(100vh - 160px);
  overflow: auto;
  position: relative;
  width: 100%; }
  @media screen and (min-width: 960px), print {
    .modal-content,
    .modal-card {
      margin: 0 auto;
      max-height: calc(100vh - 40px);
      min-width: 960px; } }

</style>