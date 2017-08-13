<template>
  <div>
    <b-message type="is-danger" has-icon v-if="appsLoadErr">
      {{ appsLoadErr }}
    </b-message>

    <div v-else>
      <div class="field is-pulled-right">
        <b-field>
          <b-radio-button v-model="view" native-value="grid">
            <b-icon icon="view_comfy"></b-icon> Grid
          </b-radio-button>
          <b-radio-button v-model="view" native-value="large">
            <b-icon icon="hdr_strong"></b-icon> Large
          </b-radio-button>
          <b-radio-button v-model="view" native-value="small">
            <b-icon icon="hdr_weak"></b-icon> Small
          </b-radio-button>
        </b-field>
      </div>

      <div class="content"><h2 class="title">Select an App to inspect</h2>
        <a class="button is-light" :href="'/api/screenshot/' + device.id" target="_blank">
          <b-icon icon="camera"></b-icon> <span>Screenshot</span></a>
      </div>

      <div class="is-clearfix">
        <ul v-if="isGrid" class="app-list">
          <li v-for="app in apps" :key="app.identifier" :class="{'is-success': app.pid }">
            <router-link :to="{ name: 'inspect', params: { device: device.id, bundle: app.identifier } }">
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

        <b-table v-else
          :data="apps"
          :narrowed="isSmallIcon"
          :hasDetails="false"
          :loading="loadingApps"
          default-sort="name">

          <template scope="props">
            <b-table-column field="smallIcon" width="16" label="" v-show="isSmallIcon">
              <icon :icon="props.row.smallIcon"></icon>
            </b-table-column>

            <b-table-column field="largeIcon" width="32" label="" v-show="isLargeIcon">
              <icon :icon="props.row.largeIcon"></icon>
            </b-table-column>

            <b-table-column field="name" label="Name" sortable>
              <router-link :to="{ name: 'inspect', params: { device: device.id, bundle: props.row.identifier } }">{{ props.row.name }}</router-link>
            </b-table-column>

            <b-table-column field="identifier" label="Bundle ID" sortable>
              {{ props.row.identifier }}
            </b-table-column>

            <b-table-column field="pid" label="PID" sortable>
              <span class="tag is-success" v-if="props.row.pid">{{ props.row.pid }}</span>
              <span class="tag" v-else>Not Running</span>
            </b-table-column>
          </template>

          <template slot="detail" scope="props">
            <article class="media">
              <figure class="media-left">
                <p class="image is-64x64"></p>
              </figure>
              <div class="media-content">
                <div class="content">
                  <p></p>
                </div>
              </div>
            </article>
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
import Icon from '~/components/Icon.vue'

export default {
  components: {
    Icon
  },
  watch: {
    // $route(to, from) {
    //   this.load()
    // },
    devices(to, from) {
      this.setDevice(this.$route.params.device)
      this.refreshApps()
      // todo: timer
    }
  },
  // mounted() {
  //   this.load()
  // },
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
      device: 'device',
      devices: 'devices',
      apps: 'apps',
      appsLoadErr: 'appsLoadErr',
      loadingDevices: 'loadingDevices',
      loadingApps: 'loadingApps',
    })
  },
  data() {
    return {
      deviceId: '',
      largeIcon: true,
      view: 'grid',
    }
  },
  methods: {
    // load() {
    //   this.devices && this.devices.length && this.refreshApps(this.$route.params.device)
    // },
    ...mapMutations({
      setDevice: 'setDevice',
    }),
    ...mapActions({
      refreshApps: 'refreshApps',
    })
  }
}
</script>

<style lang="scss">
.app-list {
  display: flex;
  flex-wrap: wrap;
  margin: 4em 0;

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
