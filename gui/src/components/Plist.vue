<template>
  <div class="plist-viewer">
    <h3 class="title">{{ title }}</h3>
    <b-field class="column">
      <a class="button" @click="expandAll">
        <b-icon icon="add"></b-icon>
        <span>Expand All</span>
      </a>
      <a class="button" @click="closeAll">
        <b-icon icon="remove"></b-icon>
        <span>Collapse All</span>
      </a>
      <b-input icon="search" v-model="filter" type="search" placeholder="Search keys and values..." expanded></b-input>
    </b-field>

    <ul class="is-marginless">
      <tree-view :model="tree" class="info-plist" ref="tree"></tree-view>
    </ul>
  </div>
</template>

<script>
import { debounce } from '~/lib/utils'
import TreeView from '~/components/TreeView.vue'

export default {
  components: { TreeView },
  props: {
    content: Object,
    title: String,
    rootName: String,
  },
  data() {
    return {
      filter: '',
      tree: {},
    }
  },
  mounted() {
    this.updateTree(this.content)
  },
  watch: {
    content(val) {
      this.filter = ''
      this.updateTree(val)
    },
    filter: debounce(function(val, old) {
      this.updateTree(this.content, val)
    }),
  },
  methods: {
    updateTree(root, filter) {
      let isMatch, needle
      if (filter && filter.length) {
        needle = filter.toLowerCase()
        isMatch = haystack => {
          if (!haystack) return false
          haystack = haystack.toLowerCase()

          let j = -1
          for (let i = 0; i < needle.length; i++) {
            let ch = needle.charAt(i)
            if (!ch || ch.match(/\s/)) continue

            j = haystack.indexOf(ch, j + 1)
            if (j === -1)
              return false
          }
          return true
        }
      }

      const expand = (node, preserve) => {
        if (Array.isArray(node) || typeof node === 'object') {
          let array = []

          for (let name in node) {
            if (node.hasOwnProperty(name)) {
              let val = node[name]
              let item = { name }
              let add = true

              switch (typeof val) {
                case 'string':
                  if (!preserve && needle) add = isMatch(val)
                // THERE IS NO BREAK ON PURPOSE
                case 'number':
                  item.val = val
                  break
                default:
                  // force not skipping first level children
                  let nameMatches = needle && isMatch(name)
                  item.children = expand(val, nameMatches)
                  if (needle) {
                    item.open = true
                    add = preserve || item.children.length || nameMatches
                  }
              }
              if (add)
                array.push(item)
            }
          }

          return array
        }
        console.warn('argument not supported', node)
      }

      let children = expand(root)
      this.tree = { name: this.rootName, children, open: true }
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