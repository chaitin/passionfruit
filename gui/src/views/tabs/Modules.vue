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

    <b-table class="column" :data="filtered" narrowed :loading="loading" :paginated="paginator > 0" :per-page="paginator" :selected.sync="selected" default-sort="name">
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

      <div slot="empty" class="has-text-centered">
        <div v-if="!loading">No matching module found</div>
      </div>
    </b-table>

  </div>
</template>

<script>
import { AsyncSearch, debounce } from '~/lib/utils'

export default {
  props: ['socket'],
  methods: {
    load() {
      this.loading = true
      this.socket.emit('modules', {}, modules => {
        this.modules = modules
        this.loading = false
      })
    },
    select(module) {
      let { name } = module
      this.loading = true
      this.socket.emit('exports', { module: name }, exports => {
        this.loading = false
        this.exports = exports
      })
    },
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
    selected(val, old) {
      if (val && val.name)
        this.select(val)
    },
  },
  data() {
    return {
      loading: true,
      filter: '',
      filtered: [],
      matcher: null,
      modules: [],
      selected: {},
      exports: [],
      paginator: 100,
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

</style>