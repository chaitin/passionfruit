<template>
  <div>
    <loading-tab v-if="loading"></loading-tab>

    <section class="section columns" v-else>
      <div class="column content">
        <h3 class="title">Binary</h3>
        <b-field grouped group-multiline>
          <div class="control">
            <b-taglist attached>
              <b-tag type="is-light">Encrypted</b-tag>
              <b-tag type="is-dark">{{ sec.encrypted ? 'YES' : 'NO' }}</b-tag>
            </b-taglist>
          </div>

          <div class="control">
            <b-taglist attached>
              <b-tag type="is-light">PIE</b-tag>
              <b-tag type="is-success" v-if="sec.arc">ENABLED</b-tag>
              <b-tag type="is-warning" v-else>N/A</b-tag>
            </b-taglist>
          </div>

          <div class="control">
            <b-taglist attached>
              <b-tag type="is-light">ARC</b-tag>
              <b-tag type="is-success" v-if="sec.arc">ENABLED</b-tag>
              <b-tag type="is-success" v-else>N/A</b-tag>
            </b-taglist>
          </div>

          <div class="control">
            <b-taglist attached>
              <b-tag type="is-light">Canary</b-tag>
              <b-tag type="is-success" v-if="sec.canary">ENABLED</b-tag>
              <b-tag type="is-warning" v-else>N/A</b-tag>
            </b-taglist>
          </div>
        </b-field>
        <b-field label="Path">
          <p>{{ info.binary }}</p>
        </b-field>
        <b-field label="Bundle">
          <p>{{ info.bundle }}</p>
        </b-field>
        <b-field label="Data Directory">
          <p>{{ info.data }}</p>
        </b-field>
        <b-field label="Version">
          <p>{{ info.semVer }}</p>
        </b-field>

        <div v-if="info.urls">
          <h3>URL Scheme</h3>
          <b-panel collapsible v-for="url in info.urls" :key="url.name">
            <span slot="header">{{ url.name || '(empty name)' }}</span>
            <ul>
              <li v-for="scheme in url.schemes" :key="scheme">{{ scheme }}://</li>
            </ul>
          </b-panel>
        </div>
      </div>

      <b-panel class="column" collapsible v-if="tree">
        <span slot="header">Metainfo</span>
        <div class="content">
          <b-field class="column">
            <a class="button" @click="expandAll"><b-icon icon="add"></b-icon><span>Expand all</span></a>
            <a class="button" @click="closeAll"><b-icon icon="remove"></b-icon><span>Close all</span></a>
            <b-input icon="search" v-model="filter" type="search"
              placeholder="Search metainfo..." expanded></b-input>
          </b-field>

          <ul class="is-marginless">
            <tree-view :model="tree" class="info-plist" ref="tree"></tree-view>
          </ul>
        </div>
      </b-panel>
    </section>
  </div>
</template>

<script>
import { mapGetters } from 'vuex'
import { GET_SOCKET } from '~/vuex/types'
import { debounce } from '~/lib/utils'
import LoadingTab from '~/components/LoadingTab.vue'
import TreeView from '~/components/TreeView.vue'

export default {
  components: { LoadingTab, TreeView },
  data() {
    return {
      loading: true,
      tree: null,
      filter: '',
      info: {},
      sec: {},
    }
  },
  computed: {
    ...mapGetters({
      socket: GET_SOCKET,
    })
  },
  watch: {
    socket(val, old) {
      this.load(val)
    },
    filter: debounce(function(val, old) {
      // todo

    }),
  },
  mounted() {
    this.load(this.socket)
  },
  methods: {
    toTree(root) {
      const expand = node => {
        if (Array.isArray(node) || typeof node === 'object') {
          return Object.keys(node).map(name => {
            let val = node[name]
            let result = { name }
            if (/^string|number$/.exec(typeof val))
              result.val = val
            else
              result.children = expand(val)

            return result
          })
        }
        console.warn('argument not supported', node)
      }

      let children = expand(root)
      return { name: 'Info.plist', children }
    },
    load(socket) {
      if (!socket)
        return // todo: error message

      this.loading = true
      socket.emit('info', {}, ({ info, sec }) => {
        this.loading = false
        this.info = info
        this.filter = ''
        this.tree = this.toTree(info.json)
        this.sec = sec

        console.log(this.tree)
      })
    },
    expandAll() {
      this.$refs.tree.toggleAll(true)
    },
    closeAll() {
      this.$refs.tree.toggleAll(false)
    }
  }
}
</script>
