<template>
  <div>
    <nav class="breadcrumb nav-bar level-left" aria-label="breadcrumbs">
      <ul class="level-item">
        <li><a @click="home"><b-icon icon="home"></b-icon></a></li>
        <li v-for="(name, index) in components" :key="name"><a @click="up(index)"><b-icon icon="folder"></b-icon><span>{{ name }}</span></a></li>
      </ul>
    </nav>

    <div class="columns">
      <div class="column is-three-quarter">
        <b-table class="column" :data="list" narrowed :loading="loading" default-sort="name" :selected.sync="selected" @dblclick="open">
          <template scope="props">
            <b-table-column field="name" label="Name" sortable>
              <b-icon icon="folder" v-if="props.row.type == 'directory' "></b-icon>
              <b-icon icon="insert_drive_file" v-else></b-icon>
              <span class="break-all">{{ props.row.name }}</span>
            </b-table-column>

            <b-table-column field="owner" label="Owner" sortable width="120">
              {{ props.row.attribute.owner }}
            </b-table-column>

            <b-table-column field="protection" label="Protection" sortable width="240" class="break-all">
              {{ props.row.attribute.protection }}
            </b-table-column>

            <b-table-column field="size" label="Size" class="monospace" sortable width="120">
              {{ props.row.attribute.size | filesize }}
            </b-table-column>
          </template>
        </b-table>
      </div>

      <div v-if="selected" class="column is-one-quarter content">
        <h3 class="title">{{ selected.name }}</h3>
        <p class="break-all"><small>{{ selected.path }}</small></p>
        <b-field v-show="selected.type != 'directory'">
          <b-tooltip v-for="(arr, type) in typesMapping" :key="type" :label="arr[0]">
            <a class="button" @click="view(type)"><b-icon :icon="arr[1]"></b-icon></a>
          </b-tooltip>
        </b-field>
        <file-viewer :type="type" :file="selected" :open.sync="viewerOpen"></file-viewer>
        <ul class="break-all" v-if="selected.type != 'directory'">
          <li>Group: {{ selected.attribute.group }}</li>
          <li>Owner: {{ selected.attribute.owner }}</li>
          <li>Created: {{ selected.attribute.creation }}</li>
          <li>Modified: {{ selected.attribute.modification }}</li>
        </ul>
      </div>
    </div>
  </div>
</template>

<script>
import { mapGetters, mapMutations } from 'vuex'
import { GET_SOCKET, FINDER_ROOT } from '~/vuex/types'
import FileViewer from '~/views/FileViewer.vue'


const FILE_TYPE_MAPPING = {
  sql: ['SQLite Editor', 'storage'],
  text: ['Text Viewer', 'mode_edit'],
  image: ['Image Viewer', 'image'],
  plist: ['PList Viewer', 'settings_applications'],
}


export default {
  components: {
    FileViewer,
  },
  computed: {
    ...mapGetters({
      socket: GET_SOCKET,
    })
  },
  data() {
    return {
      loading: false,
      root: null,
      path: null,
      components: [],
      list: [],
      selected: null,
      typesMapping: FILE_TYPE_MAPPING,
      type: null,
      viewerOpen: false,
    }
  },
  mounted() {
    this.home()
  },
  methods: {
    view(type) {
      this.type = type
      this.viewerOpen = true
    },
    home() {
      this.components = []
      this.load(this.root)
    },
    up(index) {
      if (index === this.components.length - 1)
        return

      this.components = this.components.slice(0, index + 1)
      this.load(this.root + '/' + this.components.join('/'))
    },
    open(item) {
      if (item.type === 'directory') {
        this.components.push(item.name)
        this.load(item.path)
      }
    },
    load(directory) {
      this.loading = true
      this.socket.call('ls', directory).then(({ path, list }) => {
        if (!directory) {
          this.root = path
        }
        this.path = path
        this.loading = false
        this.list = list
        this.selected = null
      })
    },
  }
}
</script>

<style lang="scss" scoped>
.break-all {
  word-break: break-all;
}
</style>