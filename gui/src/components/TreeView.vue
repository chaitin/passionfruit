<template>
  <li class="treeview">
    <div :class="{bold: isFolder}" @click="toggle" v-if="model">
      <span class="toggle" :class="{ open }" v-if="isFolder">
        <b-icon icon="expand_more"></b-icon>
      </span>
      <span v-else>
        <b-icon icon="bubble_chart"></b-icon>
      </span>
      <span class="key">{{ model.name }}</span>
      <code class="value" v-if="!isFolder">{{ model.val }}</code>
    </div>
    <ul v-show="open" v-if="isFolder">
      <tree class="item" v-for="child in children" :ref="'child_' + child.name" :key="child.name" :model="child">
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
    },
    toggleAll(status) {
      this.open = status
      if (this.isFolder) {
        this.children.forEach(child => {
          let list = this.$refs[`child_` + child.name]
          if (list && list.length) {
            let [vm, ] = list
            vm.toggleAll(status)
          }
        })
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
    .key,
    .toggle {
      cursor: pointer;
    }

    .toggle {
      .icon {
        transform: rotate(-90deg);
        transition: transform 0.2s ease-in-out;
      }
      &.open .icon {
        transform: rotate(0);
      }
    }
  }
  ul {
    margin: 0;
    padding-left: 1.5em;
    line-height: 1.5em;
  }
}
</style>
