<template>
  <div>
    <nav class="breadcrumb nav-bar level-left" aria-label="breadcrumbs">
      <ul class="level-item">
        <li class="root-indicator">
          <a @click="home" title="Home" :class="{ on: root === 'home'}">
            <b-icon icon="home"></b-icon> <span>Data</span>
          </a>
          <a @click="bundle" title="App Bundle" :class="{ on: root === 'bundle'}">
            <b-icon icon="work"></b-icon> <span>App Bundle</span>
          </a>
        </li>
        <li v-for="(name, index) in components" :key="name">
          <a @click="up(index)">
            <b-icon icon="folder"></b-icon>
            <span>{{ name }}</span>
          </a>
        </li>
      </ul>
    </nav>

    <div class="columns">
      <div class="column is-three-quarter">
        <b-table class="fixed finder" :data="list" narrowed :loading="loading"
            default-sort="name" :selected.sync="selected" @dblclick="open">
          <template slot-scope="props">
            <b-table-column field="name" label="Name" sortable class="ellipsis">
              <a class="filename" @click="open(props.row)">
                <b-icon icon="folder" v-if="props.row.type == 'directory' "></b-icon>
                <b-icon icon="insert_drive_file" v-else></b-icon>
                <span> {{ props.row.name }}</span>
              </a>
            </b-table-column>

            <b-table-column field="owner" label="Owner" sortable width="120">
              {{ props.row.attribute.owner }}
            </b-table-column>

            <b-table-column field="protection" label="Protection" sortable width="240" class="ellipsis">
              <span :title="props.row.attribute.protection">{{ props.row.attribute.protection }}</span>
            </b-table-column>

            <b-table-column field="size" label="Size" class="monospace ellipsis" sortable width="120">
              {{ props.row.attribute.size | filesize }}
            </b-table-column>
          </template>
        </b-table>

        <p class="section is-size-7">For full featured filesystem management, try
          <a class="has-text-info" href="http://pro.itools.cn/mac/english">iTools</a>,
          <a class="has-text-info" href="http://www.i-funbox.com/">iFunbox</a> or
          <a class="has-text-info" href="https://github.com/libimobiledevice/ifuse/wiki">iFuse</a> instead.</p>
      </div>

      <div v-if="selected" class="column is-one-quarter content">
        <h3 class="title">{{ selected.name }}</h3>
        <p class="break-all">
          <small>{{ selected.path }}</small>
        </p>
        <b-field v-show="selected.type != 'directory'">
          <p class="control" v-for="(arr, type) in typesMapping" :key="type">
            <b-tooltip :label="arr[0]">
              <a class="button is-primary" @click="view(type)">
                <b-icon :icon="arr[1]"></b-icon>
              </a>
            </b-tooltip>
          </p>
        </b-field>
        <file-viewer :type="type" :file="selected" :open.sync="viewerOpen"></file-viewer>
        <ul class="break-all " v-if="selected.type != 'directory'">
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
import { GET_SOCKET } from '~/vuex/types'
import FileViewer from '~/components/FileViewer.vue'
import { download, save } from '~/lib/utils'


const FILE_TYPE_MAPPING = {
  text: ['Text Viewer', 'mode_edit'],
  sql: ['SQLite Viewer', 'storage'],
  image: ['Image Viewer', 'image'],
  plist: ['PList Viewer', 'settings_applications'],
  download: ['Download', 'file_download'],
}

export default {
  components: { FileViewer },
  computed: {
    components() {
      return this.cwd ? this.cwd.split('/') : []
    },
    ...mapGetters({
      socket: GET_SOCKET,
    }),
  },
  data() {
    return {
      loading: false,
      root: 'home',
      cwd: '',
      list: [],
      selected: null,
      typesMapping: FILE_TYPE_MAPPING,
      type: null,
      viewerOpen: false,
    }
  },
  mounted() {
    this.load(this.$route.query)
  },
  watch: {
    $route(val) {
      this.load(val.query)
    },
  },
  methods: {
    view(type) {
      if (type === 'download') {
        let { name } = this.selected
        download(this.socket, this.selected).then(save(name))
        return
      }
      this.type = type
      this.viewerOpen = true
    },
    relative(tail) {
      // todo: shall we support ".." ?
      return this.cwd.length ? [this.cwd, tail].join('/') : tail
    },
    cd(path, newRoot) {
      if (this.loading)
        return this.$toast.open('busy...')

      this.$router.push({
        query: {
          root: newRoot || this.root,
          path,
        }
      })
    },
    async load({ root, path }) {
      this.root = ['root', 'bundle'].indexOf(root) > -1 ? root : 'home'
      this.cwd = path || ''

      this.loading = true
      try {
        const { cwd, list } = await this.socket.call('ls', {
          pathName: this.cwd,
          root: this.root,
        })
        this.list = list
        if(this.list.length === 0 && path === 'Library/Caches/Snapshots') {
          this.$toast.open({
          message: `Operation not permitted`,
          type: 'is-danger',
          })
        }
      } catch(ex) {
        this.$toast.open({
          message: `failed to change current directory: ${ex}`,
          type: 'is-danger',
        })
        console.error(ex.stack || ex)
      }
      
      this.selected = null
      this.loading = false
    },
    up(index) {
      const { components } = this
      if (index === components.length - 1) return
      this.cd(components.slice(0, index + 1).join('/'))
    },
    open(item) {
      if (item.type === 'directory') {
        this.cd(this.relative(item.name))
      } else {
        let ext = item.name.split('.').slice(-1).pop()
        const mapping = {
          'db': 'sql',
          'sqlite': 'sql',
          'png': 'image',
          'jpg': 'image',
          'jpeg': 'image',
          'gif': 'image', // gif is now supported by iOS
          'plist': 'plist',
        }
        this.view(mapping[ext] || 'text')
      }
    },
    home() {
      this.cd('', 'home')
    },
    bundle() {
      this.cd('', 'bundle')
    },
  }
}
</script>

<style lang="scss">
.finder {
  user-select: none;
  a.filename {
    cursor: pointer;
  }
}

.root-indicator a.on {
  color: #222;
  font-weight: bold;
}
</style>
