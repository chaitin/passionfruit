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
      <div class="modal-card" v-if="symbol">
        <header class="modal-card-head">
          <p class="modal-card-title">{{ module }}!{{ symbol.name }}</p>
        </header>

        <section class="modal-card-body">
          <!-- <p class="subtitle is-6">
              <span v-if="symbol.address.value">
                0x{{ symbol.address.value.toString(16) }}</span>
              <span v-else>{{ symbol.address }}</span>
            </p> -->

          <p>Arguments</p>

          <b-field v-for="(arg, index) in args" :key="index">
            <b-select placeholder="Argument type" v-model="arg.type" expanded>
              <option v-for="(t, j) in types" :key="j" :value="t">{{ t }}</option>
            </b-select>
            <p class="control">
              <button class="button is-danger" @click="removeArg(index)">
                <b-icon icon="remove_circle_outline"></b-icon>
              </button>
            </p>
          </b-field>

          <b-field>
            <button @click="addArg" class="button">
              <b-icon icon="add_circle_outline"></b-icon>
              <span>Add</span>
            </button>
          </b-field>

          <b-field>
            <code>{{ expr }}</code>
          </b-field>

        </section>

        <footer class="modal-card-foot confirm-footer">
          <button class="button" type="button" @click="symbolDialogActive = false">Dismiss</button>
          <button class="button is-primary" @click="hook">Send to Interceptor</button>
        </footer>
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
      args: [],
      types: ['int', 'uint', 'long', 'ulong', 'char', 'uchar', 'char *',
        'int8', 'uint8', 'int16', 'uint16', 'int32', 'uint32', 'int64', 'uint64'],
      ret: 'void',
    }
  },
  methods: {
    openSymbolDetail(symbol) {
      this.symbolDialogActive = true
      this.args = []
      this.ret = 'void'
      this.symbol = symbol
    },
    addArg() {
      this.args.push({ type: 'char *' })
    },
    removeArg(index) {
      this.args.splice(index, 1)
    },
    paginate(page, filtered, paginator) {
      this.slice = filtered.slice((page - 1) * paginator, page * paginator)
    },
    hook() {
      // todo
    },
  },
  computed: {
    expr() {
      return this.symbol.name + '(' + this.args.map(t => t.type).join(', ') + ')'
    }
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

.confirm-footer {
  justify-content: flex-end;
}
</style>
