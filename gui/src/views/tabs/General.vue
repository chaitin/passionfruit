<template>
  <div>
    <loading-tab v-if="loading"></loading-tab>

    <section class="columns" v-else>
      <div class="column content">
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
          <p>{{ info.bundle }}</p>
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

        <hr>

        <div v-if="info.urls">
          <h3>URL Scheme</h3>
          <b-panel collapsible v-for="url in info.urls" :key="url.name">
            <span slot="header">{{ url.name || '(empty name)' }}</span>
            <ul>
              <li v-for="scheme in url.schemes" :key="scheme">
                <router-link :to="{ name: 'uiopen', params: { device: device.id, scheme } }">
                  {{ scheme }}://
                </router-link>
              </li>
            </ul>
          </b-panel>
        </div>
      </div>

      <div class="column content" v-if="metainfo">
        <plist title="Metainfo" :content="metainfo" rootName="Info.plist"></plist>
      </div>
    </section>
  </div>
</template>

<script>
import { mapGetters } from 'vuex'
import { GET_SOCKET, GET_DEVICE } from '~/vuex/types'
import LoadingTab from '~/components/LoadingTab.vue'
import Plist from '~/components/Plist.vue'
import Url from '~/components/URLScheme.vue'


export default {
  components: { LoadingTab, Plist, Url },
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
