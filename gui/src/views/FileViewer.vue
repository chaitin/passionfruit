<template>
  <div>
    <b-modal :active.sync="active" :width="1200">
      <section class="dialog section">
        <loading-tab v-if="loading"></loading-tab>
        <div v-else>
          <b-message type="is-danger" v-if="error">{{ error }}</b-message>
          <article class="content" v-if="content">
            <plist v-if="type == 'plist'" title="Plist Reader" :content="content" :rootName="file.name"></plist>
            <hex-view v-if="type == 'text'" :raw="content"></hex-view>
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
import HexView from '~/components/HexView.vue'


export default {
  components: { LoadingTab, Plist, HexView },
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

section.dialog {
  background: #fff;
  min-height: 50vh;
}

.modal-content,
.modal-card {
  margin: 0 20px;
  max-height: calc(100vh - 160px);
  overflow: auto;
  position: relative;
  width: 100%;
}

@media screen and (min-width: 960px),
print {
  .modal-content,
  .modal-card {
    margin: 0 auto;
    max-height: calc(100vh - 40px);
    min-width: 960px;
  }
}
</style>