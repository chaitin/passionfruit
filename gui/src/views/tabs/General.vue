<template>
  <div>
    <loading-tab v-if="loading"></loading-tab>

    <section class="columns is-mobile" v-else>
      <div class="column content is-half-desktop is-one-third-fullhd">
        <h3 class="title">Binary</h3>
        <b-field grouped group-multiline>
          <div class="control">
            <b-taglist attached>
              <b-tag type="is-light">Encrypted</b-tag>
              <b-tag type="is-dark">{{ sec.encrypted ? 'YES' : 'NO' }}</b-tag>
            </b-taglist>
          </div>

          <div class="control">
            <b-taglist attached>
              <b-tag type="is-light">PIE</b-tag>
              <b-tag type="is-success" v-if="sec.pie">ENABLED</b-tag>
              <b-tag type="is-warning" v-else>N/A</b-tag>
            </b-taglist>
          </div>

          <div class="control">
            <b-taglist attached>
              <b-tag type="is-light">ARC</b-tag>
              <b-tag type="is-success" v-if="sec.arc">ENABLED</b-tag>
              <b-tag type="is-success" v-else>N/A</b-tag>
            </b-taglist>
          </div>

          <div class="control">
            <b-taglist attached>
              <b-tag type="is-light">Canary</b-tag>
              <b-tag type="is-success" v-if="sec.canary">ENABLED</b-tag>
              <b-tag type="is-warning" v-else>N/A</b-tag>
            </b-taglist>
          </div>
        </b-field>
        <b-field label="Identifier">
          <p>{{ info.id }}</p>
        </b-field>
        <b-field label="Bundle">
          <p>
            <router-link class="has-text-info" :to="{ name: 'files', query: { root: 'bundle' } }">
              {{ info.bundle }}</router-link>
          </p>
        </b-field>
        <b-field label="Executable">
          <p>{{ info.binary }}</p>
        </b-field>
        <b-field label="Data Directory">
          <p>
            <router-link class="has-text-info" :to="{ name: 'files' }">{{ info.data }}</router-link>
          </p>
        </b-field>
        <b-field label="Version">
          <p>{{ info.semVer }}</p>
        </b-field>
        <b-field label="Entitlements" v-if="sec.entitlements">
          <data-field :field="{ key: 'entitlements', value: sec.entitlements }" :depth="0">
          </data-field>
        </b-field>

      </div>

      <div class="column content is-half-desktop is-one-third-fullhd" v-if="info.urls">
        <h3>URL Scheme</h3>
        <b-panel collapsible v-for="(url, index) in info.urls" :key="index">
          <span slot="header">{{ url.name || '(empty name)' }}</span>
          <ul>
            <li v-for="scheme in url.schemes" :key="scheme">
              <router-link :to="{ name: 'uiopen', params: {
                  device: device.id,
                  bundle: app.identifier,
                  scheme
                }
              }">
                {{ scheme }}://
              </router-link>
            </li>
          </ul>
        </b-panel>

      </div>

      <div class="column content is-half-desktop is-one-third-fullhd" v-if="metainfo">
        <plist title="Metainfo" :content="metainfo" rootName="Info.plist"></plist>
      </div>
    </section>
  </div>
</template>

<script>
import { mapGetters } from 'vuex'
import { GET_SOCKET, GET_DEVICE, GET_ALL, GET_APP } from '~/vuex/types'

import DataField from '~/components/DataField.vue'
import LoadingTab from '~/components/LoadingTab.vue'
import Plist from '~/components/Plist.vue'


export default {
  components: { DataField, LoadingTab, Plist },
  data() {
    return {
      loading: true,
      info: {},
      sec: {},
      metainfo: null,
    }
  },
  computed: {
    ...mapGetters({
      app: GET_APP,
      socket: GET_SOCKET,
      device: GET_DEVICE,
    })
  },
  mounted() {
    this.load()
  },
  methods: {
    load(socket) {
      this.loading = true
      this.socket.call('info').then(({ info, sec }) => {
        this.loading = false
        this.info = info
        this.metainfo = info.json
        this.sec = sec
      })
    },
  }
}
</script>
