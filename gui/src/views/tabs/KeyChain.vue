<template>
  <div class="keychain">

    <b-table :data="list" narrowed hasDetails :loading="loading" default-sort="clazz" detailed>
      <template slot-scope="props">
        <b-table-column field="clazz" label="Class" sortable width="120">
          <b-tag>{{ props.row.clazz | trim('kSecClass') }}</b-tag>
        </b-table-column>

        <b-table-column field="account" label="Account" sortable>
          <span class="break-all">{{ props.row.account }}</span>
        </b-table-column>

        <b-table-column field="data" label="Data">
          <code class="break-all">{{ props.row.data }}</code>
        </b-table-column>

        <b-table-column field="accessibleAttribute" label="Accessible Attribute" width="180" sortable>
          <b-tag type="is-info">{{ props.row.accessibleAttribute | trim('kSecAttrAccessible') }}</b-tag>
        </b-table-column>
      </template>

      <template slot="detail" slot-scope="props">
        <article>
          <ul class="keychain-attributes">
            <li v-for="(title, key) in columns" :key="key">
              <dl>
                <dt>{{ title }}</dt>
                <dd>{{ props.row[key] }}</dd>
              </dl>
            </li>
          </ul>

        </article>
      </template>

      <div slot="empty" class="has-text-centered">
        <p v-show="!loading">Empty result</p>
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
    const columns = {}
    const keys = ['service', 'label', 'creation', 'modification', 'description', 'entitlementGroup',
      'comment', 'creator', 'type', 'scriptCode', 'alias', 'invisible',
      'negative', 'customIcon', 'protected', 'accessControl', 'generic', ]
    keys.forEach(key => columns[key] = key.replace(/([a-z](?=[A-Z]))/g, '$1 '))

    return {
      columns,
      list: [],
      loading: false,
    }
  },
  filters: {
    trim(val, prefix) {
      return val.indexOf(prefix) === 0 ? val.substr(prefix.length) : val
    }
  },
  computed: {
    ...mapGetters({
      socket: GET_SOCKET,
    })
  },
  methods: {
    load(socket) {
      this.loading = true
      this.socket.call('dumpKeyChain')
        .then(list => this.list = list)
        .finally(() => this.loading = false)
    },
  },
  mounted() {
    this.load()
  }
}
</script>

<style lang="scss">
ul.keychain-attributes {
  display: flex;
  flex-wrap: wrap;
  li {
    display: inline-block;
    width: 360px;

    dl {
      margin-bottom: 12px;
      dt {
        font-size: .75rem;
        color: #888;
      }
      dd {
        min-height: 1em;
      }
    }
  }
}
</style>
