<template>
  <div>
    <loading-tab v-if="loading"></loading-tab>

    <div v-else>
      <b-field class="column">
        <b-input icon="search" v-model="filter" type="search" placeholder="Filter..." expanded></b-input>
        <b-select v-model="paginator">
          <option value="50">50 per page</option>
          <option value="100">100 per page</option>
          <option value="200">200 per page</option>
        </b-select>
        <p class="search-stat">{{ filtered.length }} / {{ list.length }}</p>
      </b-field>

      <ul class="oc-classes">
        <li v-for="clz in slice" :key="clz">{{ clz }}</li>
      </ul>

      <b-pagination :total="filtered.length" :current.sync="page" order="is-centered" :per-page="paginator">
      </b-pagination>
    </div>
  </div>
</template>

<script>
import { mapGetters } from 'vuex'
import LoadingTab from '~/components/LoadingTab.vue'
import { GET_SOCKET } from '~/vuex/types'
import { AsyncSearch, debounce } from '~/lib/utils'


export default {
  components: { LoadingTab },
  computed: {
    ...mapGetters({
      socket: GET_SOCKET,
    })
  },
  data() {
    return {
      loading: false,
      list: [],
      filtered: [],
      slice: [],
      page: 1,
      filter: '',
      paginator: 100,
      matcher: null,
    }
  },
  watch: {
    filter: debounce(function(val, old) {
      this.matcher.search(val)
    }),
    page(val, old) {
      this.paginate(val, this.filtered, this.paginator)
    },
    filtered(val, old) {
      this.paginate(this.page, val, this.paginator)
    },
    paginator(val, old) {
      this.paginate(this.page, this.filtered, val)
    },
    list(val, old) {
      this.filter = ''
      this.filtered = val
      this.matcher.update(val)
      this.page = 1
    }
  },
  methods: {
    load(socket) {
      this.loading = true
      socket.call('classes').then(classes => {
        this.list = classes
        this.loading = false
      })
    },
    paginate(page, filtered, paginator) {
      this.slice = filtered.slice((page - 1) * paginator, page * paginator).sort()
    },
  },
  mounted() {
    this.matcher = new AsyncSearch().onMatch(result => {
      this.filtered = result
    })
    this.load(this.socket)
  },
}
</script>

<style lang="scss">
ul.oc-classes {
  display: flex;
  flex-wrap: wrap;
  padding: 0 1em;

  li {
    display: block;
    padding: 4px;
    overflow: hidden;

    @for $i from 1 through 3 {
      @media screen and (min-width: $i * 360px) {
        width: round(percentage(1 / $i))
      }
    }
  }
}

p.search-stat {
  font-size: 0.75em;
  line-height: 2.25em;
  margin-left: 1em;
}
</style>
