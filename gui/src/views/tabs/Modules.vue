<template>
  <div>
    <b-field class="column">
      <b-input icon="search" v-model="filter" type="search" placeholder="Filter modules..." expanded></b-input>
      <b-select v-model="paginator">
        <option value="0">Don't paginate</option>
        <option value="50">50 per page</option>
        <option value="100">100 per page</option>
        <option value="200">200 per page</option>
      </b-select>
    </b-field>

    <b-table class="column" :data="filtered" narrowed :loading="loading" :paginated="paginator > 0" :per-page="paginator" :selected.sync="selected" default-sort="name" detailed @details-open="openDetail">
      <template scope="props">
        <b-table-column field="name" label="Name" sortable>
          {{ props.row.name }}
        </b-table-column>

        <b-table-column field="baseAddress" label="Base" class="monospace" sortable>
          {{ props.row.baseAddress.value.toString(16) }}
        </b-table-column>

        <b-table-column field="size" label="Size" class="monospace" sortable>
          {{ props.row.size }}
        </b-table-column>

        <b-table-column field="path" label="Path" class="break-all">
          {{ props.row.path }}
        </b-table-column>
      </template>

      <template slot="detail" scope="props">
        <loading-tab v-if="props.row.loading"></loading-tab>
        <article v-else class="content">
          <h4 class="title">Exported Symbols</h4>
          <ul class="exports" v-if="props.row.exports.length">
            <li v-for="symbol in props.row.exports" :key="symbol.name">
              <b-icon icon="functions" v-show="symbol.type == 'function'"></b-icon>
              <b-icon icon="title" v-show="symbol.type == 'symbol'"></b-icon>
              {{ symbol.name }}
            </li>
          </ul>

          <b-message v-else>This module has no exported symbol</b-message>
        </article>
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
import LoadingTab from '~/components/LoadingTab.vue'

export default {
  components: {
    LoadingTab,
  },
  methods: {
    load(socket) {
      if (!socket)
        return

      this.loading = true
      socket.emit('modules', {}, modules => {
        this.modules = modules.map(mod =>
          Object.assign({
            loading: false, exports: []
          }, mod))
        this.loading = false
      })
    },
    openDetail(mod) {
      if (mod.detailed)
        return

      mod.loading = true
      mod.exports = []
      mod.detailed = true
      this.socket.emit('exports', { module: mod.name }, list => {
        mod.loading = false
        mod.exports = list
      })
    },
  },
  computed: {
    ...mapGetters({
      socket: GET_SOCKET,
    })
  },
  watch: {
    socket(val, old) {
      this.load(val)
    },
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
      selected: {}, // currently ignore it
      paginator: 100,
    }
  },
  mounted() {
    this.matcher = new AsyncSearch([], 'name')
      .onMatch(result => this.filtered = result)
    this.load(this.socket)
  }
}
</script>

<style lang="scss">
ul.exports {
  display: flex;
  flex-wrap: wrap;
  padding: 0;
  margin: 0;

  li {
    display: block;
    overflow: hidden;
    padding: 0 4px;

    @for $i from 1 through 4 {
      @media screen and (min-width: $i * 360px) {
        width: round(percentage(1 / $i))
      }
    }

    .icon {
      word-break: initial;
      color: #b3b3b3;
    }

    word-break: break-all;
  }
}
</style>