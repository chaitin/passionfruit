<template>
  <div>
    <loading-tab v-if="loading"></loading-tab>
    <section class="section" v-else>
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
            <b-tag type="is-success" v-if="sec.arc">ENABLED</b-tag>
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
      <b-field label="Path">
        <p>{{ info.binary }}</p>
      </b-field>
      <b-field label="Bundle">
        <p>{{ info.bundle }}</p>
      </b-field>
      <b-field label="Data Directory">
        <p>{{ info.data }}</p>
      </b-field>
      <b-field label="Version">
        <p>{{ info.semVer }}</p>
      </b-field>

      <div v-if="info.urls">
        <h3>Urls</h3>
        <b-panel collapsible v-for="url in info.urls" :key="url.name">
          <span slot="header">{{ url.name || '(empty name)' }}</span>
          <ul>
            <li v-for="scheme in url.schemes" :key="scheme">{{ scheme }}://</li>
          </ul>
        </b-panel>
      </div>

      <b-panel collapsible v-if="info.json">
        <span slot="header">Info.plist</span>
        <div class="content">
          <a class="button" @click="expandAll">Expand all</a>
          <a class="button" @click="closeAll">Close all</a>
          <ul>
            <tree-view :model="{ name: 'root', val: info.json }" class="info-plist" ref="tree"></tree-view>
          </ul>
        </div>
      </b-panel>
    </section>
  </div>
</template>

<script>
import LoadingTab from '~/components/LoadingTab.vue'
import TreeView from '~/components/TreeView.vue'

export default {
  components: { LoadingTab, TreeView },
  props: ['socket'],
  data() {
    return {
      loading: true,
      info: {},
      sec: {}
    }
  },
  methods: {
    load() {
      this.loading = true
      this.socket.emit('info', {}, ({ info, sec }) => {
        this.loading = false
        this.info = info
        this.sec = sec
      })
    },
    expandAll() {
      this.$refs.tree.toggleAll(true)
    },
    closeAll() {
      this.$refs.tree.toggleAll(false)
    }
  },
  mounted() {
    this.load()
  }
}
</script>

