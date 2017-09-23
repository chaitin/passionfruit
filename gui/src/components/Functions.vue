<template>
  <div>
    <b-field>
      <b-input icon="search" v-model="filter" type="search" placeholder="Filter..." expanded></b-input>
    </b-field>

    <ul class="functions content column">
      <li v-for="symbol in slice" :key="symbol.name">
        <b-icon icon="functions"></b-icon>
        <span class="name" @click="openSymbolDetail(symbol)">{{ symbol.name }}</span>
      </li>
    </ul>

    <b-pagination :total="filtered.length" :current.sync="page" order="is-centered" :per-page="paginator"></b-pagination>

    <b-modal :active.sync="symbolDialogActive" :width="640">
      <div class="card" v-if="symbol">
        <div class="card-content">
          <div class="media">
            <div class="media-content">
              <p class="title is-4">{{ module }}!{{ symbol.name }}</p>
              <p class="subtitle is-6">
                <span v-if="symbol.address.value">
                  0x{{ symbol.address.value.toString(16) }}</span>
                <span v-else>{{ symbol.address }}</span>
              </p>

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
import { AsyncSearch, debounce } from '~/lib/utils'

export default {
  props: {
    loading: Boolean,
    list: Array,
    module: String,
  },
  watch: {
    list(val, old) {
      this.filter = ''
      this.filtered = val
      this.matcher.update(val)
    },
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
    },
    filter: debounce(function(val, old) {
      this.matcher.search(val)
    }),
  },
  data() {
    return {
      filter: '',
      filtered: this.list,
      page: 1,
      slice: [],
      paginator: 100,
      matcher: null,

      // selected symbol
      symbolDialogActive: false,
      symbol: null,
    }
  },
  methods: {
    openSymbolDetail(symbol) {
      this.symbolDialogActive = true
      this.symbol = symbol
    },
    paginate(page, filtered, paginator) {
      this.slice = filtered.slice((page - 1) * paginator, page * paginator)
    },
  },
  mounted() {
    this.matcher = new AsyncSearch(this.list, 'name').onMatch(result => {
      this.filtered = result
    })
    this.paginate(this.page, this.filtered, this.paginator)
  }
}
</script>

<style lang="scss">
ul.functions {
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
