<template>
  <div>
    <b-field>
      <b-input icon="search" v-model="filter" type="search" placeholder="Filter modules..." expanded></b-input>
      <b-select v-model="paginator">
        <option value="0">Don't paginate</option>
        <option value="50">50 per page</option>
        <option value="100">100 per page</option>
        <option value="200">200 per page</option>
      </b-select>
    </b-field>

    <b-table class="fixed" :data="filtered" narrowed :loading="loading" :paginated="paginator > 0" :per-page="paginator" default-sort="name" detailed @details-open="openDetail">
      <template scope="props">
        <b-table-column field="name" label="Name" sortable width="320">
          <b-tooltip label="Dump decrypted">
            <a class="button is-small is-dark" @click="dump(props.row.name)">
              <b-icon icon="system_update_alt"></b-icon>
            </a>
          </b-tooltip>
          <span>{{ props.row.name }}</span>
        </b-table-column>

        <b-table-column field="baseAddress" label="Base" class="monospace" sortable width="120">
          0x{{ props.row.baseAddress.value.toString(16) }}
        </b-table-column>

        <b-table-column field="size" label="Size" class="monospace" sortable width="120">
          {{ props.row.size }}
        </b-table-column>

        <b-table-column field="path" label="Path" class="break-all">
          {{ props.row.path }}
        </b-table-column>
      </template>

      <template slot="detail" scope="props">
        <loading-tab v-if="props.row.loading"></loading-tab>

        <div class="content" v-if="props.row.imports">
          <h4 class="title">Imports</h4>
          <functions :list="props.row.imports" :loading="loading" :module="props.row.name"></functions>
        </div>

        <div class="content" v-if="props.row.exports.length">
          <h4 class="title">Exports</h4>
          <functions :list="props.row.exports" :loading="props.row.loading" :module="props.row.name"></functions>
        </div>
        <b-message v-else>This module has no exported symbol</b-message>

      </template>

      <div slot="empty" class="has-text-centered">
        <div v-if="!loading">No matching module found</div>
      </div>
    </b-table>

  </div>
</template>

<script>
import { mapGetters } from 'vuex'
import { GET_SOCKET } from '~/vuex/types'
import { AsyncSearch, debounce } from '~/lib/utils'
import { download, save } from '~/lib/utils'

import LoadingTab from '~/components/LoadingTab.vue'
import Functions from '~/components/Functions.vue'

export default {
  components: { LoadingTab, Functions },
  methods: {
    async load() {
      this.loading = true
      let modules = await this.socket.call('modules')
      this.modules = modules.map((mod, index) =>
        Object.assign({
          loading: false,
          exports: [],
        }, mod))

      let imports = await this.socket.call('imports')
      this.imports = imports.filter(imp => imp.type === 'function')
      this.modules[0].imports = this.imports
      this.loading = false
    },
    async dump(name) {
      this.loading = true
      try {
        let path = await this.socket.call('dumpdecrypted', name)
        this.$dialog.confirm({
          title: 'Dump successful',
          message: `File dumped to: \n ${path}`,
          cancelText: 'Dismiss',
          confirmText: 'Download',
          type: 'is-success',
          onConfirm: () => {
            setImmediate(() => {
              download(this.socket, { path }).then(save(name))
            })
          }
        })
      } catch(ex) {
        this.$toast.open({
          duration: 10 * 1000,
          message: ex,
          type: 'is-danger',
        })
      } finally {
        this.loading = false
      }
    },
    openDetail(mod, index) {
      if (mod.detailed)
        return

      mod.loading = true
      mod.detailed = true
      this.socket.call('exports', { module: mod.name }).then(list => {
        mod.loading = false
        mod.exports = list.filter(exp => exp.type === 'function')
      })
    },
  },
  computed: {
    ...mapGetters({
      socket: GET_SOCKET,
    })
  },
  watch: {
    modules(val, old) {
      this.filter = ''
      this.filtered = val
      this.matcher.update(val)
    },
    filter: debounce(function(val, old) {
      this.matcher.search(val)
    }),
  },
  data() {
    return {
      loading: true,
      filter: '',
      filtered: [],
      matcher: null,
      modules: [],
      paginator: 100,
      imports: [],
    }
  },
  mounted() {
    this.matcher = new AsyncSearch([], 'name')
      .onMatch(result => this.filtered = result)
    this.load()
  }
}
</script>

<style lang="scss">
.monospace {
  font-family: monospace;
}
</style>