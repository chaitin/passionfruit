<template>
  <div>
    <b-table class="column fixed" :data="cookies" narrowed :loading="loading" default-sort="name">
      <template slot-scope="props">
        <b-table-column field="name" label="Name" sortable width="160">
          <span class="break-all">{{ props.row.name }}</span>
        </b-table-column>
        <b-table-column field="value" label="Value">
          <span class="break-all">{{ props.row.value }}</span>
        </b-table-column>
        <b-table-column field="domain" label="Domain" sortable width="200">
          <span class="break-all">{{ props.row.domain }}</span>
        </b-table-column>
        <b-table-column field="path" label="Path" width="120">
          <span class="break-all">{{ props.row.path }}</span>
        </b-table-column>
        <b-table-column field="secure" label="Secure" width="80">
          <b-checkbox disabled v-model="props.row.isSecured"></b-checkbox>
        </b-table-column>
      </template>

      <div slot="empty" class="has-text-centered">
        <p v-show="!loading"><b-icon icon="info"></b-icon> <span>No binary cookie found</span></p>
      </div>
    </b-table>
  </div>
</template>

<script>
import { mapGetters } from 'vuex'
import LoadingTab from '~/components/LoadingTab.vue'
import { GET_SOCKET } from '~/vuex/types'

export default {
  computed: {
    ...mapGetters({
      socket: GET_SOCKET,
    })
  },
  mounted() {
    this.load()
  },
  data() {
    return {
      loading: false,
      cookies: [],
    }
  },
  methods: {
    load() {
      this.loading = true
      this.socket.call('cookies')
        .then(cookies => this.cookies = cookies)
        .finally(this.loading = false)
    }
  }
}
</script>

<style>

</style>
