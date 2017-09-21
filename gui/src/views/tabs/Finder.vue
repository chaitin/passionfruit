<template>
  <div>
    <nav class="breadcrumb nav-bar level-left" aria-label="breadcrumbs">
      <ul class="level-item">
        <li v-for="name in path" :key="name">{{ name }}</li>
      </ul>
    </nav>

    <b-table class="column" :data="current.children" narrowed :loading="loading" default-sort="name">
      <template scope="props">
        <b-table-column field="name" label="Name" sortable>
          <b-icon icon="folder" v-if="props.row.type == 'directory' "></b-icon>
          <b-icon icon="insert_drive_file" v-else></b-icon>
          <span>{{ props.row.name }}</span>
        </b-table-column>

        <b-table-column field="attribute" label="Owner" sortable width="120">
          {{ props.row.attribute.owner }}
        </b-table-column>

        <b-table-column field="size" label="Size" class="monospace" sortable width="120">
          {{ props.row.attribute.size }}
        </b-table-column>
      </template>
    </b-table>
  </div>
</template>

<script>
import { mapGetters, mapMutations } from 'vuex'
import { GET_SOCKET, FINDER_ROOT } from '~/vuex/types'
import FolderTree from '~/components/FolderTree.vue'


export default {
  components: {
    FolderTree,
  },
  computed: {
    ...mapGetters({
      socket: GET_SOCKET,
      root: FINDER_ROOT,
    })
  },
  watch: {
    socket(val, old) {
      this.load(val)
    },
  },
  data() {
    return {
      loading: false,
      path: [this.root],
      current: {},
      tree: {
        name: '',
        path: null,
        children: []
      }
    }
  },
  mounted() {
    this.load(this.socket, this.tree)
  },
  methods: {
    load(socket, node) {
      this.loading = true
      this.current = node
      socket.emit('ls', node.path, ({ path, list }) => {
        this.loading = false
        if (!node.path) {
          node.path = path
          this.path = [path]
        }
        node.children = list
      })
    },
    ...mapMutations({
      open: FINDER_ROOT,
    })
  }
}
</script>