<template>
  <div class="container is-fluid">
    <header class="level is-marginless">
      <nav class="breadcrumb nav-bar level-left" aria-label="breadcrumbs">
        <ul class="level-item">
          <li>
            <a href="/">ipaspect</a>
          </li>
          <li>
            <router-link v-if="device.id" :to="{name: 'apps', params: {device: device.id}}">
              <icon :icon="device.icon"></icon> {{ device.name }}</router-link>
          </li>
          <li class="is-active">
            <a href="#" v-if="app" aria-current="page">
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
              <b-icon icon="camera"></b-icon>
            </a>
          </b-tooltip>
          <b-tooltip label="Kill Process" position="is-left">
            <button class="button is-danger" @click="kill">
              <b-icon icon="exit_to_app"></b-icon>
            </button>
          </b-tooltip>
        </nav>
      </div>
    </header>

    <b-message v-if="err" type="is-danger" has-icon>{{ err }}</b-message>
    <b-loading :active="loading" :canCancel="true" @cancel="home"></b-loading>

    <div v-if="connected">
      <b-tabs position="is-centered" :expanded="true" :animated="false">
        <b-tab-item label="General">
          <general-view :socket="socket"></general-view>
        </b-tab-item>

        <b-tab-item label="Modules">
          <modules-view :loading="modules.loading" :list="modules" @reload:modules="loadModules" @expand:module="loadModuleInfo"></modules-view>
        </b-tab-item>

        <b-tab-item label="Ranges">
          <b-field grouped group-multiline class="column">
            <div class="control is-flex">
              <b-switch v-model="ranges.filter.x">Executable</b-switch>
            </div>
            <div class="control is-flex">
              <b-switch v-model="ranges.filter.r">Readable</b-switch>
            </div>
            <div class="control is-flex">
              <b-switch v-model="ranges.filter.w">Writable</b-switch>
            </div>
            <div class="control is-flex">
              <b-select v-model="ranges.paginator">
                <option value="0">Don't paginate</option>
                <option value="50">50 per page</option>
                <option value="100">100 per page</option>
                <option value="200">20 per page</option>
              </b-select>
            </div>
          </b-field>
          <b-table class="monospace ranges" :data="ranges.list" :narrowed="true" :hasDetails="false" :paginated="ranges.paginator > 0" :per-page="ranges.paginator" default-sort="name">

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
          <classes-view :socket="socket"></classes-view>
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

import ModulesView from '~/views/tabs/Modules.vue'
import GeneralView from '~/views/tabs/General.vue'
import ClassesView from '~/views/tabs/Classes.vue'

export default {
  components: {
    Icon,
    ModulesView,
    GeneralView,
    ClassesView,
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
      this.modules.loading = true
      this.socket.emit('modules', {}, modules => {
        this.modules = modules
        this.modules.loading = false
      })
    },
    paginateClasses(page, filtered, paginator) {
      this.classes.slice = filtered.slice(
        (page - 1) * paginator, page * paginator).sort()
    },
    home() {
      this.$route.push({ name: 'welcome' })
    },
    kill() {
      this.$dialog.confirm({
        title: 'Kill App',
        message: 'Are you sure you want to <b>kill</b> the process? The session will end.',
        confirmText: 'Kill',
        type: 'is-danger',
        hasIcon: true,
        onConfirm: () => {
          this.$router.push({ name: 'apps', params: this.$route.params })
          this.socket.emit('kill', {}, result => {
            if (result) {
              this.$toast.open(`${bundle} has been terminiated`)
            }
          })
        }
      })
    },
    createSocket() {
      let { device, bundle } = this.$route.params
      return io('/session', { path: '/msg' })
        .on('attached', console.info.bind(console))
        .on('close', console.warn.bind(console))
        .on('disconnect', () => {
          this.err = 'Application connection is closed'
          this.connected = false
        })
        .on('device', dev => this.device = dev)
        .on('app', app => this.app = app)
        .on('ready', () => {
          this.loading = false
          this.connected = true

          this.loadModules()
          this.loadRanges()
        })
        .on('err', err => {
          this.err = err
        })
        .emit('attach', { device, bundle }, data => {
          if (data.status == 'error') {
            this.$toast.open(`failed to attach to ${bundle}`)
            this.err = data.message
            this.modules.loading = this.ranges.loading = false
          }
        })
    }
  },
  data() {
    const socket = this.createSocket()
    return {
      err: '',
      loading: true,
      connected: false,
      app: {},
      socket,
      device: {},

      modules: [],

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

ul.exports {
  font-size: 0.875em;
  padding: 10px;
}

.ranges {
  max-width: 720px;
}

.search {
  margin-top: 0;
}
</style>
