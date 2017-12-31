<template>
  <div>
    <b-message type="is-danger" has-icon v-if="deviceDetailErr">
      {{ deviceDetailErr }}
    </b-message>

    <b-message type="is-danger" has-icon v-if="appsLoadErr">
      {{ appsLoadErr }}
    </b-message>

    <div v-else>
      <header class="level">
        <div v-if="deviceDetailLoading" class="level-left"><loading></loading></div>

        <div v-if="deviceDetail" class="device-detail level-left">
          <div class="field is-grouped is-grouped-multiline">
            <div class="control">
              <div class="tags has-addons">
                <span class="tag is-dark">{{ deviceDetail.DeviceName }}</span>
                <span class="tag">{{ deviceDetail.ProductName }} {{ deviceDetail.ProductVersion }}</span>
              </div>
            </div>
            <div class="control">
              <div class="tags has-addons">
                <span class="tag is-dark">Hardware</span>
                <span class="tag">{{ deviceDetail.HardwareModel }}</span>
              </div>
            </div>
            <div class="control">
              <div class="tags has-addons">
                <span class="tag is-dark">Serial</span>
                <span class="tag">{{ deviceDetail.SerialNumber }}</span>
              </div>
            </div>
          </div>
        </div>

        <b-field class="level-right">
          <b-dropdown v-model="view" is-align="right">
            <button class="button is-light" slot="trigger">
              <b-icon v-if="isGrid" icon="view_comfy"></b-icon>
              <b-icon v-if="isLargeIcon" icon="hdr_strong"></b-icon>
              <b-icon v-if="isSmallIcon" icon="hdr_weak"></b-icon>
              <span>Display</span>
              <b-icon icon="arrow_drop_down"></b-icon>
            </button>
            <b-dropdown-item value="grid">
              <b-icon icon="view_comfy"></b-icon> Grid</b-dropdown-item>
            <b-dropdown-item value="large">
              <b-icon icon="hdr_strong"></b-icon> Large</b-dropdown-item>
            <b-dropdown-item value="small">
              <b-icon icon="hdr_weak"></b-icon> Small</b-dropdown-item>
          </b-dropdown>
          <a class="button is-light" :href="'/api/device/' + device.id + '/screenshot'" target="_blank">
            <b-icon icon="camera"></b-icon>
            <span>Screenshot</span>
          </a>
        </b-field>
      </header>

      <div class="is-clearfix">
        <ul v-if="isGrid" class="app-list">
          <li v-for="app in apps" :key="app.identifier" :class="{'is-success': app.pid }">
            <router-link :to="{ name: 'general', params: { device: device.id, bundle: app.identifier } }">
              <icon :icon="app.largeIcon" class="icon"></icon>
              <div class="content">
                <h3 :class="{ 'is-success': app.pid }">{{ app.name }} </h3>
                <p class="has-text-grey">{{ app.identifier }}</p>
                <!-- <div class="tags has-addons" v-if="app.pid">
                            <span class="tag is-success">pid</span>
                            <span class="tag">{{ app.pid }}</span>
                          </div> -->
              </div>
            </router-link>
          </li>
        </ul>

        <b-table v-else :data="apps" :narrowed="isSmallIcon" :hasDetails="false" :loading="loadingApps" default-sort="name">

          <template scope="props">
            <b-table-column field="smallIcon" width="16" label="" v-show="isSmallIcon">
              <icon :icon="props.row.smallIcon"></icon>
            </b-table-column>

            <b-table-column field="largeIcon" width="32" label="" v-show="isLargeIcon">
              <icon :icon="props.row.largeIcon"></icon>
            </b-table-column>

            <b-table-column field="name" label="Name" sortable>
              <router-link :to="{ name: 'general', params: { device: device.id, bundle: props.row.identifier } }">{{ props.row.name }}</router-link>
            </b-table-column>

            <b-table-column field="identifier" label="Bundle ID" sortable>
              {{ props.row.identifier }}
            </b-table-column>

            <b-table-column field="pid" label="PID" sortable>
              <span class="tag is-success" v-if="props.row.pid">{{ props.row.pid }}</span>
              <span class="tag" v-else>Not Running</span>
            </b-table-column>
          </template>

          <div slot="empty" class="has-text-centered">
            Please select a device
          </div>
        </b-table>
      </div>
    </div>
  </div>
</template>

<script>
import { mapActions, mapGetters, mapMutations } from 'vuex'

import {
  SELECT_DEVICE,
  GET_DEVICE,
  GET_DEVICES,
  LOAD_APPS,
  APPS_ERROR,
  LOAD_DEVICE_DETAIL,
  DEVICE_DETAIL_LOADING,
  DEVICE_DETAIL_ERROR,
  APPS_LOADING,
  DEVICES_LOADING,
  GET_DEVICE_DETAIL,
  GET_APPS,
  DEVICE_ERROR,
} from '~/vuex/types'
import Icon from '~/components/Icon.vue'
import Loading from '~/components/Loading.vue'

export default {
  components: {
    Icon,
    Loading,
  },
  watch: {
    $route() {
      if (this.checkDevices(this.devices))
        this.select()
    },
    devices(value) {
      if (this.checkDevices(value))
        this.select()
    },
    device(value, old) {
      if (value.id != old.id || !this.apps.length)
        this.refreshApps()
    }
  },
  computed: {
    isGrid() {
      return this.view == 'grid'
    },
    isSmallIcon() {
      return this.view == 'small'
    },
    isLargeIcon() {
      return this.view == 'large'
    },
    ...mapGetters({
      device: GET_DEVICE,
      deviceErr: DEVICE_ERROR,
      devices: GET_DEVICES,
      deviceDetail: GET_DEVICE_DETAIL,
      deviceDetailLoading: DEVICE_DETAIL_LOADING,
      deviceDetailErr: DEVICE_DETAIL_ERROR,
      apps: GET_APPS,
      appsLoadErr: APPS_ERROR,
      loadingDetail: DEVICE_DETAIL_LOADING,
      loadingApps: APPS_LOADING,
    })
  },
  data() {
    return {
      deviceId: '',
      largeIcon: true,
      view: 'grid',
    }
  },
  mounted() {
    if (this.devices.length)
      this.select()
  },
  methods: {
    checkDevices(devices) {
      let id = this.$route.params.device
      if (!devices.length) {
        this.$toast.open(`device ${id} no longer connected`)
        this.home()
        return false
      }
      return true
    },
    home() {
      this.$router.push({ 'name': 'welcome' })
    },
    select(devices) {
      let id = this.$route.params.device
      this.selectDevice(id)
      this.loadDeviceDetail()
    },
    ...mapMutations({
      selectDevice: SELECT_DEVICE,
    }),
    ...mapActions({
      refreshApps: LOAD_APPS,
      loadDeviceDetail: LOAD_DEVICE_DETAIL,
    })
  }
}
</script>

<style lang="scss">
.device-detail {
  padding-top: 0.5em;
}

.app-list {
  display: flex;
  flex-wrap: wrap;
  margin: 2em 0;

  li {
    display: block;
    padding: 4px;
    overflow: hidden;

    @for $i from 1 through 4 {
      @media screen and (min-width: $i * 360px) {
        width: round(percentage(1 / $i))
      }
    }

    .icon {
      float: left;
      width: 32px;
      height: 32px;
    }

    .content {
      margin-left: 2.75em;
    }

    a {
      display: block;
      padding: 10px;
      border-radius: 4px;
      transition: background-color, .2s;

      &:hover {
        background: #f7f7f7;
      }
    }

    h3 {
      margin-bottom: 0.25em;
    }

    p {
      text-overflow: ellipsis;
    }
  }
}
</style>
