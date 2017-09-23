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

    <b-table class="column" :data="filtered" narrowed :loading="loading" :paginated="paginator > 0" :per-page="paginator" default-sort="name" detailed @details-open="openDetail">
      <template scope="props">
        <b-table-column field="name" label="Name" sortable width="320">
          {{ props.row.name }}
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
        <!-- TODO: paginate -->
        <div class="content" v-if="props.index == 0">
          <h4 class="title">Imports</h4>
          <ul class="imports content">
            <li v-for="symbol in imports" :key="symbol.name">
              <b-icon icon="functions"></b-icon>
              <span class="name" @click="openSymbolDetail(props.row, symbol)">{{ symbol.name }}</span>
            </li>
          </ul>
        </div>

        <div class="content" v-if="props.row.exports.length">
          <h4 class="title">Exports</h4>
          <ul class="exports">
            <li v-for="symbol in props.row.exports" :key="symbol.name">
              <b-icon icon="functions"></b-icon>
              <span class="name" @click="openSymbolDetail(props.row, symbol)">{{ symbol.name }}</span>
            </li>
          </ul>
        </div>
        <b-message v-else>This module has no exported symbol</b-message>

      </template>

      <div slot="empty" class="has-text-centered">
        <div v-if="!loading">No matching module found</div>
      </div>
    </b-table>

    <b-modal :active.sync="symbolDialogActive" :width="640">
      <div class="card" v-if="symbol.symbol">
        <div class="card-content">
          <div class="media">
            <div class="media-content">
              <p class="title is-4">{{ symbol.mod.name }}!{{ symbol.symbol.name }}</p>
              <p class="subtitle is-6">
                <span v-if="symbol.symbol.address.value">
                  0x{{ symbol.symbol.address.value.toString(16) }}</span>
                <span v-else>{{ symbol.symbol.address }}</span></p>

              <p>Todo: Set argument types</p>
              <p>
                <a class="button">
                  <b-icon icon="add"></b-icon>
                  <span>Add to Interceptor</span>
                </a>
              </p>
            </div>
          </div>

        </div>
      </div>
    </b-modal>
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
    load() {
      this.loading = true
      this.socket.call('imports').then(list => {
        this.imports = list.filter(imp => imp.type === 'function')
        this.socket.call('modules').then(modules => {
          this.modules = modules.map((mod, index) =>
            Object.assign({
              loading: false,
              exports: [],
            }, mod))
          this.loading = false
        })
      })
    },
    openSymbolDetail(mod, symbol) {
      this.symbolDialogActive = true
      this.symbol = { mod, symbol }
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

      // selected symbol
      symbolDialogActive: false,
      symbol: {},
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

ul.exports, ul.imports {
  display: flex;
  flex-wrap: wrap;
  padding: 0;
  margin: 0;
  width: 100%;

  li {
    display: block;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
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

    .name {
      font-family: monospace;
      cursor: pointer;
    }
  }
}
</style>