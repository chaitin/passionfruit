<template>
  <div class="ranges">
    <b-field grouped group-multiline class="column">
      <div class="control is-flex">
        <b-switch v-model="filter.x">Executable</b-switch>
      </div>
      <div class="control is-flex">
        <b-switch v-model="filter.r">Readable</b-switch>
      </div>
      <div class="control is-flex">
        <b-switch v-model="filter.w">Writable</b-switch>
      </div>
      <div class="control is-flex">
        <b-select v-model="paginator">
          <option value="0">Don't paginate</option>
          <option value="50">50 per page</option>
          <option value="100">100 per page</option>
          <option value="200">20 per page</option>
        </b-select>
      </div>
    </b-field>

    <b-table class="monospace" :data="list" :narrowed="true" :hasDetails="false" :paginated="paginator > 0" :per-page="paginator" :loading="loading" default-sort="name">
      <template scope="props">
        <b-table-column field="baseAddress" label="Base" sortable>
          {{ props.row.baseAddress.value.toString(16) }}
        </b-table-column>

        <b-table-column field="size" label="Size" sortable>
          {{ props.row.size }}
        </b-table-column>

        <b-table-column field="protection" label="Protection">
          {{ props.row.protection }}
        </b-table-column>
      </template>

      <div slot="empty" class="has-text-centered">
        No matching range
      </div>
    </b-table>

  </div>
</template>

<script>
import { mapGetters } from 'vuex'
import { GET_SOCKET } from '~/vuex/types'

import LoadingTab from '~/components/LoadingTab.vue'

export default {
  components: { LoadingTab },
  data() {
    return {
      list: [],
      filtered: [],
      loading: true,
      paginator: 100,
      filter: {
        x: true,
        w: false,
        r: true,
      },
    }
  },
  computed: {
    ...mapGetters({
      socket: GET_SOCKET,
    })
  },
  watch: {
    filter: {
      handler() {
        this.load()
      },
      deep: true
    },
  },
  methods: {
    load(socket) {
      let protection = Object.keys(this.filter)
        .filter(key => this.filter[key])
        .join('')

      this.loading = true
      this.socket.call('ranges', { protection: protection }).then(ranges => {
        this.list = ranges
        this.loading = false
      })
    },
  },
  mounted() {
    this.load()
  }
}
</script>

<style lang="scss">
.ranges {
  max-width: 720px;
  margin: auto;
}
</style>
