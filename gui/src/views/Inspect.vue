<template>
  <div class="container is-fluid">
    <header class="level is-marginless">
      <nav class="breadcrumb nav-bar level-left" aria-label="breadcrumbs">
        <ul class="level-item">
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

      <div class="level-right">
        <nav class="level-item">
          <b-tooltip label="Screenshot" position="is-left">
            <a class="button is-light" :href="'/api/device/' + device.id + '/screenshot'" target="_blank">
            <b-icon icon="camera"></b-icon></a>
          </b-tooltip>
          <b-tooltip label="Kill Process" position="is-left">
            <button class="button is-danger" @click="kill"><b-icon icon="exit_to_app"></b-icon></button>
          </b-tooltip>
        </nav>
      </div>
    </header>

    <b-message v-if="err" type="is-danger" has-icon>{{ err }}</b-message>
    <b-loading :active="loading.modules || general.loading || ranges.loading"
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
          <modules :loading="loading.modules" :list="modules" @reload:modules="loadModules" @expand:module="loadModuleInfo"></modules>
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
            class="monospace ranges"
            :data="ranges.list"
            :narrowed="true"
            :hasDetails="false"
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

        <b-tab-item label="Classes">
          <b-field class="column">
            <b-input icon="search" v-model="classes.filter" type="search"
              placeholder="Filter classes..." expanded></b-input>
            <b-select v-model="classes.paginator">
              <option value="50">50 per page</option>
              <option value="100">100 per page</option>
              <option value="200">200 per page</option>
            </b-select>
            <p class="search-stat">{{ classes.filtered.length }} / {{ classes.list.length }}</p>
          </b-field>

          <ul class="oc-classes">
            <li v-for="clz in classes.slice" :key="clz">{{ clz }}</li>
          </ul>

          <b-pagination
            :total="classes.filtered.length"
            :current.sync="classes.page"
            order="is-centered"
            :per-page="classes.paginator">
          </b-pagination>
        </b-tab-item>
      </b-tabs>
    </div>
  </div>
</template>

<script>

import io from 'socket.io-client'
import { mapGetters, mapActions, mapMutations } from 'vuex'
import { AsyncSearch, debounce } from '~/lib/utils'

import Icon from '~/components/Icon.vue'
import Modules from '~/views/Modules.vue'


export default {
  components: {
    Icon,
    Modules
  },
  watch: {
    // todo: detect device removal
    app(val, old) {
      if (val.name)
        document.title = `ipaspect: ${val.name}`
    },
    'ranges.filter': {
      handler() {
        this.loadRanges()
      },
      deep: true
    },
    'classes.filter': debounce(function(val, old) {
      this.classes.matcher.search(val)
    }),
    ['classes.list'](val, old) {
      this.classes.filter = ''
      this.classes.filtered = val
      this.classes.matcher.update(val)
    },
    ['classes.page'](val, old) {
      this.paginateClasses(val, this.classes.filtered, this.classes.paginator)
    },
    ['classes.filtered'](val, old) {
      this.paginateClasses(this.classes.page, val, this.classes.paginator)
    },
    ['classes.paginator'](val, old) {
      this.paginateClasses(this.classes.page, this.classes.filtered, val)
    },
  },
  methods: {
    loadModuleInfo(module) {
      return

      // todo: dialog
      let { name } = module
      this.loading.moduleInfo = true
      this.socket.emit('exports', { module: name }, exports => {
        this.loading.moduleInfo = false
      //   selected.exports = exports
      })
    },
    loadRanges() {
      let protection = Object.keys(this.ranges.filter)
        .filter(key => this.ranges.filter[key])
        .join('')

      this.ranges.loading = true
      this.socket.emit('ranges', { protection: protection }, ranges => {
        this.ranges.list = ranges
        this.ranges.loading = false
      })
    },
    loadModules() {
      this.loading.modules = true
      this.socket.emit('modules', {}, modules => {
        this.modules = modules
        this.loading.modules = false
      })
    },
    loadClasses() {
      this.classes.loading = true
      this.socket.emit('classes', {}, classes => {
        this.classes.list = classes
        this.classes.loading = false
        this.classes.matcher = new AsyncSearch(classes)
        this.classes.matcher.onMatch(result => this.classes.filtered = result)
        this.classes.page = 1
        this.classes.filtered = []
      })
    },
    paginateClasses(page, filtered, paginator) {
      this.classes.slice = filtered.slice(
        (page - 1) * paginator, page * paginator).sort()
    },
    kill() {
      this.$dialog.confirm({
        title: 'Kill App',
        message: 'Are you sure you want to <b>kill</b> the process? The session will end.',
        confirmText: 'Kill',
        type: 'is-danger',
        hasIcon: true,
        onConfirm: () => {
          this.$router.push({name: 'apps', params: this.$route.params})
          this.socket.emit('kill', {}, result => {
            if (result) {
              this.$toast.open(`${bundle} has been terminiated`)
            }
          })
        }
      })
    },
    loadInfo() {
      this.general.loading = true
      this.socket.emit('info', {}, ({sec, info}) => {
        this.general.loading = false
        if (sec)
          this.general.sec = sec
        if (info)
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
          this.loadClasses() // will probably slow down
        })
        .on('err', err => {
          this.err = err
        })
        .emit('attach', { device, bundle }, data => {
          if (data.status == 'error') {
            this.$toast.open(`failed to attach to ${bundle}`)
            this.err = data.message
            this.loading.modules = false
            this.general.loading = this.ranges.loading = false
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
      modules: [],
      loading: {
        modules: false,
      },

      // modules: {
      //   list: [],
      //   filter: '',
      //   filtered: [],
      //   matcher: null,
      //   loading: true,
      //   paginator: 100,
      //   selected: {
      //     item: {},
      //     exports: [],
      //     name: null,
      //   },
      // },

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
      },

      classes: {
        list: [],
        filtered: [],
        slice: [],
        page: 1,
        filter: '',
        loading: false,
        paginator: 100,
      },

      methods: {
        clazz: '',
        list: [],
        loading: false,
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
  margin: 10px 0;

  canvas {
    margin-right: 4px;
  }
}

.monospace {
  font-family: monospace;
}

.break-all {
  word-break: break-all;
}

ul.oc-classes {
  display: flex;
  flex-wrap: wrap;
  padding: 0 1em;

  li {
    display: block;
    padding: 4px;
    overflow: hidden;

    @for $i from 1 through 3 {
      @media screen and (min-width: $i * 360px) {
        width: round(percentage(1 / $i))
      }
    }
  }
}

ul.exports {
  font-size: 0.875em;
  padding: 10px;
}

p.search-stat {
  font-size: 0.75em;
  line-height: 2.25em;
  margin-left: 1em;
}

.ranges {
  max-width: 720px;
}

.search {
  margin-top: 0;
}

</style>
