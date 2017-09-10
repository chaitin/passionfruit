<template>
  <li class="treeview">
    <div :class="{bold: isFolder}" @click="toggle" v-if="model">
      <span v-if="isFolder">
        <b-icon icon="expand_less" v-if="open"></b-icon>
        <b-icon icon="expand_more" v-else></b-icon>
      </span>
      <span v-else>
        <b-icon icon="bubble_chart"></b-icon>
      </span>
      <span class="key">{{ model.name }}</span>
      <code class="value" v-if="!isFolder">{{ model.val }}</code>
    </div>
    <ul v-show="open" v-if="isFolder">
      <tree class="item" v-for="child in children" :key="child.name" :model="child">
      </tree>
    </ul>

  </li>
</template>

<script>

export default {
  name: 'tree',
  props: ['model'],
  data() {
    return {
      open: false
    }
  },
  computed: {
    name() {
      if (model)
        return model.name || 'root'
    },
    children() {
      if (!this.model)
        return this.model

      let val = this.model.val
      if (/^string|number$/.exec(typeof val)) {
        return null
      }

      if (Array.isArray(val) || typeof val === 'object') {
        return Object.keys(val).map(key => ({
          name: key,
          val: val[key]
        }))
      } else {
        throw new Error(`unknown type: ${val}`)
      }
    },
    isFolder() {
      return this.children && this.children.length
    }
  },
  methods: {
    toggle() {
      if (this.isFolder) {
        this.open = !this.open
      }
    }
  }
}
</script>

<style lang="scss">
.treeview {
  list-style: none;

  .key::after {
    content: ":";
    font-family: monospace;
  }
  .bold {
    font-weight: bold;
    .key {
      cursor: pointer;
    }
  }
  ul {
    margin: 0;
    padding-left: 1.5em;
    line-height: 1.5em;
  }
}
</style>
