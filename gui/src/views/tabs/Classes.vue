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
        <li v-for="clz in slice" :key="clz" :title="clz" @click="expand(clz)">{{ clz }}</li>
      </ul>

      <!-- todo: search -->
      <b-modal :active.sync="showDialog" :width="1200">
        <div class="card">
          <div class="card-content">
            <loading-tab v-if="loadingMethods"></loading-tab>

            <div v-else>
              <h4 class="title">{{ selected }}</h4>
              <ul class="oc-methods">
                <li v-for="(method, index) in methods" :key="index" @click="toggleHook(method)">
                  <b-icon icon="fiber_manual_record" class="is-small" :class="{ 'has-text-danger': method.hooked }"></b-icon>
                  <span class="break-all monospace">{{ method.name }}</span>
                </li>
              </ul>
            </div>
          </div>
        </div>
      </b-modal>

      <b-pagination :total="filtered.length" :current.sync="page" order="is-centered" :per-page="paginator">
      </b-pagination>
    </div>
  </div>
</template>

<script>
import { mapGetters } from 'vuex'
import LoadingTab from '~/components/LoadingTab.vue'
import { GET_SOCKET, IS_OBJC_HOOKED, IS_SYMBOL_HOOKED } from '~/vuex/types'
import { AsyncSearch, debounce } from '~/lib/utils'


export default {
  components: { LoadingTab },
  computed: {
    ...mapGetters({
      isObjCHooked: IS_OBJC_HOOKED,
      isSymbolHooked: IS_SYMBOL_HOOKED,
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

      showDialog: false,
      loadingMethods: false,
      selected: null,
      methods: [],
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
    load() {
      this.loading = true
      this.socket.call('classes')
        .then(classes => this.list = classes)
        .finally(() => this.loading = false)
    },
    paginate(page, filtered, paginator) {
      this.slice = filtered.slice((page - 1) * paginator, page * paginator).sort()
    },
    toggleHook(method) {
      this.$toast.open(`TODO: hook ${this.selected} ${method.name}`)
    },
    expand(clz) {
      this.showDialog = true
      this.selected = clz
      this.loadingMethods = true
      this.socket.call('methods', { clz })
        .then(methods => {
          // todo: filter
          this.methods = methods.map(name => {
            return {
              name,
              hooked: this.isObjCHooked(clz, name)
            }
          })
        })
        .finally(() => this.loadingMethods = false)
    }
  },
  mounted() {
    this.matcher = new AsyncSearch().onMatch(result => this.filtered = result)
    this.load()
  },
}
</script>

<style lang="scss">
ul.oc-classes {
  display: flex;
  flex-wrap: wrap;
  padding: 0 1em;
  cursor: pointer;
  margin-bottom: 1rem;

  li {
    display: block;
    padding: 4px;
    overflow: hidden;
    text-overflow: ellipsis;

    @for $i from 1 through 4 {
      @media screen and (min-width: $i * 360px) {
        width: round(percentage(1 / $i))
      }
    }
  }
}

ul.oc-methods {
  li {
    display: block;
    text-overflow: ellipsis;
    overflow: hidden;
    margin: 4px;
    cursor: pointer;

    &:hover {
      background: #f7f7f7;
    }
  }
}

p.search-stat {
  font-size: 0.75em;
  line-height: 2.25em;
  margin-left: 1em;
}
</style>
