<template>
  <div>
    <b-modal :active.sync="active" has-model-card>
      <loading-tab v-if="loading"></loading-tab>
      <div v-else>
        <b-message type="is-danger" v-if="error">{{ error }}</b-message>
        <article class="content">
          <div class="card">
            <div class="card-content">
              <plist v-if="type == 'plist'" title="Plist Reader" :content="content" :rootName="file.name"></plist>
            </div>
          </div>
        </article>
      </div>
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
    ...mapGetters({
      socket: GET_SOCKET,
    })
  },
  data() {
    return {
      content: {},
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
      if (this.type === 'plist') {
        this.loading = true
        this.socket.call('plist', path).then(content => {
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