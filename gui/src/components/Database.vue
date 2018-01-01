<template>
  <div>
    <b-loading v-if="loading"></b-loading>
    <div v-else>
      <b-field>
        <b-dropdown>
          <button class="button is-primary" slot="trigger">
            <span v-if="table">{{ table }}</span>
            <span v-else>Select a table</span>
            <b-icon icon="arrow_drop_down"></b-icon>
          </button>

          <div v-if="tables.length">
            <b-dropdown-item v-for="table in tables" :key="table" @click="query(table)">{{ table }}</b-dropdown-item>
          </div>
          <b-dropdown-item v-else disabled>No table in this database</b-dropdown-item>

        </b-dropdown>
      </b-field>

      <div class="overflow">
        <b-table :data="rows" v-if="table" bordered striped narrowed sortable :loading="loading">
          <template slot-scope="props">
            <template v-for="(hdr, index) in columns">
              <b-table-column :field="hdr[1]" :label="hdr[1]" :key="index">
                <template>{{ props.row[index] }}</template>
              </b-table-column>
            </template>
          </template>

          <template slot="empty">
            <section class="section">
              <div class="content has-text-grey has-text-centered">
                <p>
                  <b-icon icon="sentiment_very_dissatisfied" size="is-large">
                  </b-icon>
                </p>
                <p>No data found</p>
              </div>
            </section>
          </template>
        </b-table>

        <p class="is-size-7">Table more than 100 rows will be truncated</p>
      </div>
    </div>
  </div>
</template>

<script>
import { mapGetters } from 'vuex'
import { GET_SOCKET } from '~/vuex/types'

export default {
  props: {
    file: Object,
  },
  computed: {
    ...mapGetters({
      socket: GET_SOCKET,
    })
  },
  data() {
    return {
      tables: [],
      loading: false,
      table: null,
      columns: [],
      rows: [],
    }
  },
  methods: {
    query(table) {
      this.loading = true
      this.table = table
      this.socket.call('data', { path: this.file.path, table })
        .then(({ header, data }) => {
          this.columns = header
          this.rows = data
        })
        .finally(() => this.loading = false)
    },
    load() {
      this.loading = true
      this.socket.call('tables', this.file.path)
        .then(data => this.tables = data)
        .finally(() => this.loading = false)
    },
  },
  mounted() {
    this.load()
  }
}
</script>

<style lang="scss">
.overflow {
  overflow: auto
}
</style>
