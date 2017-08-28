<template>
  <div class="container is-fluid">
    <header>
      <nav class="breadcrumb nav-bar" aria-label="breadcrumbs">
        <ul>
          <li><a href="/">ipaspect</a></li>
          <li><router-link v-if="device.id" :to="{name: 'apps', params: {device: device.id}}">
            <icon :icon="device.icon"></icon> {{ device.name }}</router-link></li>
          <li class="is-active"><a href="#" v-if="app" aria-current="page">
            <icon :icon="app.smallIcon"></icon> {{ app.name }}</a>
            <div class="tags has-addons">
              <span class="tag is-light">{{ app.identifier }}</span>
              <span class="tag is-success" v-if="app.pid">pid: {{ app.pid }}</span>
            </div>
          </li>
        </ul>
      </nav>
    </header>

    <b-message v-if="err" type="is-danger" has-icon>{{ err }}</b-message>
    <b-loading :active="modules.loading || general.loading || ranges.loading"
      @cancel="onCancel" :canCancel="true"></b-loading>

    <div v-if="app">
      <b-tabs position="is-centered" :expanded="true" :animated="false">
        <b-tab-item label="General">
          <section class="section" v-show="!general.loading">
            <b-field grouped group-multiline>
              <div class="control">
                <b-taglist attached>
                  <b-tag type="is-light">Encrypted</b-tag>
                  <b-tag type="is-dark">{{ general.sec.encrypted ? 'YES' : 'NO' }}</b-tag>
                </b-taglist>
              </div>

              <div class="control">
                <b-taglist attached>
                  <b-tag type="is-light">PIE</b-tag>
                  <b-tag type="is-success" v-if="general.sec.arc">ENABLED</b-tag>
                  <b-tag type="is-warning" v-else>N/A</b-tag>
                </b-taglist>
              </div>

              <div class="control">
                <b-taglist attached>
                  <b-tag type="is-light">ARC</b-tag>
                  <b-tag type="is-success" v-if="general.sec.arc">ENABLED</b-tag>
                  <b-tag type="is-success" v-else>N/A</b-tag>
                </b-taglist>
              </div>

              <div class="control">
                <b-taglist attached>
                  <b-tag type="is-light">Canary</b-tag>
                  <b-tag type="is-success" v-if="general.sec.canary">ENABLED</b-tag>
                  <b-tag type="is-warning" v-else>N/A</b-tag>
                </b-taglist>
              </div>
            </b-field>
            <b-field label="Path"><p>{{ general.info.binary }}</p></b-field>
            <b-field label="Bundle"><p>{{ general.info.bundle }}</p></b-field>
            <b-field label="Data Directory"><p>{{ general.info.data }}</p></b-field>
            <b-field label="Version"><p>{{ general.info.semVer }}</p></b-field>
          </section>

        </b-tab-item>

        <b-tab-item label="Modules">
          <b-field class="column">
            <b-input icon="search" v-model="modules.filter" type="search"
              placeholder="Filter modules..." expanded></b-input>
            <b-select v-model="modules.paginator">
              <option value="0">Don't paginate</option>
              <option value="50">50 per page</option>
              <option value="100">100 per page</option>
              <option value="200">200 per page</option>
            </b-select>
          </b-field>

          <b-table
            class="monospace"
            :data="modules.filtered"
            :narrowed="true"
            :hasDetails="false"
            :loading="modules.loading"
            :paginated="modules.paginator > 0"
            :per-page="modules.paginator"
            default-sort="name">

            <template scope="props">
              <b-table-column field="name" label="Name" sortable>
                <a href="#" @click="showModuleInfo(props.row)">{{ props.row.name }}</a>
              </b-table-column>

              <b-table-column field="baseAddress" label="Base" sortable>
                {{ props.row.baseAddress.value.toString(16) }}
              </b-table-column>

              <b-table-column field="size" label="Size" sortable>
                {{ props.row.size }}
              </b-table-column>

              <b-table-column field="path" label="Path">
                {{ props.row.path }}
              </b-table-column>
            </template>

            <div slot="empty" class="has-text-centered">
              No matching module found
            </div>
          </b-table>

          <b-modal :active.sync="showModuleInfoDialog" :width="720">
            <div class="card">
              <div class="card-content">
                <div class="content">
                  <h2>Export symbols from {{ modules.selected.name }}
                    <a class="button is-loading is-light is-primary"
                      v-show="modules.selected.loading">Loading</a></h2>

                  <!-- todo: add hook! -->
                  <!-- todo: search -->
                  <ul v-if="modules.selected.exports.length || modules.selected.loading">
                    <li v-for="symbol in modules.selected.exports">
                      <b-icon icon="functions" v-show="symbol.type == 'function'"></b-icon>
                      <b-icon icon="title" v-show="symbol.type == 'symbol'"></b-icon>
                      {{ symbol.name }}
                    </li>
                  </ul>
                  <b-message v-else type="is-info" has-icon>
                    No exported symbol found
                  </b-message>
                </div>
              </div>
            </div>
          </b-modal>
        </b-tab-item>

        <b-tab-item label="Ranges">
          <b-field grouped group-multiline class="column">
            <div class="control is-flex"><b-switch v-model="ranges.filter.x">Executable</b-switch></div>
            <div class="control is-flex"><b-switch v-model="ranges.filter.r">Readable</b-switch></div>
            <div class="control is-flex"><b-switch v-model="ranges.filter.w">Writable</b-switch></div>
            <div class="control is-flex">
              <b-select v-model="ranges.paginator">
                <option value="0">Don't paginate</option>
                <option value="50">50 per page</option>
                <option value="100">100 per page</option>
                <option value="200">20 per page</option>
              </b-select>
            </div>
          </b-field>
          <b-table
            class="monospace"
            :data="ranges.list"
            :narrowed="true"
            :hasDetails="false"
            :loading="ranges.loading"
            :paginated="ranges.paginator > 0"
            :per-page="ranges.paginator"
            default-sort="name">

            <template scope="props">
              <b-table-column field="baseAddress" label="Base" sortable>
                {{ props.row.baseAddress.value.toString(16) }}
              </b-table-column>

              <b-table-column field="size" label="Size" sortable>
                {{ props.row.size }}
              </b-table-column>

              <b-table-column field="protection" label="Protection">
                {{ props.row.protection }}
              </b-table-column>
            </template>

            <div slot="empty" class="has-text-centered">
              No matching range
            </div>
          </b-table>
        </b-tab-item>

        <b-tab-item label="Todo">

        </b-tab-item>
      </b-tabs>
    </div>
  </div>
</template>

<script>

import io from 'socket.io-client'
import { mapGetters, mapActions, mapMutations } from 'vuex'
import Icon from '~/components/Icon.vue'
import { matcher, debounce } from '~/lib/utils'

export default {
  components: {
    Icon,
  },
  watch: {
    // todo: detect device removal
    app(val, old) {
      if (val.name)
        document.title = `ipaspect: ${val.name}`
    },
    'modules.filter': debounce(function(val, old) {
      this.modules.filtered = val && val.length ?
        this.modules.matcher(val) :
        this.modules.list
    }, 500),
    'ranges.filter': {
      handler() {
        this.loadRanges()
      },
      deep: true
    },
  },
  methods: {
    showModuleInfo(module) {
      this.modules.selected = {loading: true, name: module.name, exports: []}
      this.socket.emit('exports', {module: module.name}, data => {
        this.modules.selected = {loading: false, name: module.name, exports: data}
      })
      this.showModuleInfoDialog = true
    },
    loadRanges() {
      let protection = Object.keys(this.ranges.filter)
        .filter(key => this.ranges.filter[key])
        .join('')

      this.ranges.loading = false
      this.socket.emit('ranges', { protection: protection }, ranges => {
        this.ranges.list = ranges
        this.ranges.loading = false
      })
    },
    loadModules() {
      this.modules.loading = true
      this.socket.emit('modules', {}, modules => {
        this.modules.filtered = this.modules.list = modules
        this.modules.loading = false
        this.modules.matcher = matcher(modules, 'name')
      })
    },
    loadInfo() {
      this.general.loading = true
      this.socket.emit('info', {}, ({sec, info}) => {
        this.general.loading = false
        this.general.sec = sec
        this.general.info = info
      })
    },
    onCancel() {
      this.$route.push({name: 'welcome'})
    },
    createSocket() {
      let { device, bundle } = this.$route.params
      return io('/session', { path: '/msg' })
        .on('attached', console.info.bind(console))
        .on('close', console.warn.bind(console))
        .on('disconnect', () => {
          this.err = 'Application connection is closed'
        })
        .on('device', dev => this.device = dev)
        .on('app', app => this.app = app)
        .on('ready', () => {
          this.loadModules()
          this.loadRanges()
          this.loadInfo()
        })
        .on('err', err => {
          this.err = err
        })
        .emit('attach', { device, bundle }, data => {
          if (data.status == 'error') {
            this.$toast.open(`failed to attach to ${bundle}`)
            this.err = data.message
            this.general.loading = this.ranges.loading = this.modules.loading = false
          }
        })
    }
  },
  data() {
    const socket = this.createSocket()
    return {
      err: '',
      app: {},
      socket,
      device: {},

      // workaround: this can not be nested
      showModuleInfoDialog: false,
      modules: {
        list: [],
        filter: '',
        filtered: [],
        matcher: null,
        loading: true,
        paginator: 0,
        selected: {
          exports: [],
          name: null,
        },
      },

      ranges: {
        list: [],
        filtered: [],
        loading: true,
        paginator: 100,
        filter: {
          x: true,
          w: false,
          r: true,
        },
      },

      general: {
        loading: true,
        sec: {},
        info: {},
      }
    }
  },
  beforeDestroy() {
    this.socket.emit('detach')
  },
}
</script>

<style lang="scss" scoped>
.breadcrumb {
  margin: 10px auto;

  canvas {
    margin-right: 4px;
  }
}

.monospace {
  font-family: monospace;
  font-size: 14px;
}

</style>
