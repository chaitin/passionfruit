<template>
  <div>
    <div class="field is-pulled-right">
      <b-switch v-model="largeIcon">Large Icon</b-switch>
    </div>
    <div>
      <b-table
        :data="apps"
        :narrowed="!largeIcon"
        :loading="false"
        :hasDetails="false"
        default-sort="name">

        <template scope="props">
          <b-table-column field="smallIcon" width="16" label="" v-show="!largeIcon">
            <icon :icon="props.row.smallIcon"></icon>
          </b-table-column>

          <b-table-column field="largeIcon" width="32" label="" v-show="largeIcon">
            <icon :icon="props.row.largeIcon"></icon>
          </b-table-column>

          <b-table-column field="name" label="Name" sortable>
            {{ props.row.name }}
          </b-table-column>

          <b-table-column field="identifier" label="Bundle ID" sortable>
            {{ props.row.identifier }}
          </b-table-column>

          <b-table-column field="pid" label="PID" sortable>
            {{ props.row.pid }}
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
</template>

<script>
import axios from 'axios'
import Icon from './Icon.vue'

export default {
  components: {
    Icon
  },
  watch: {
    $route(from, to) {
      this.refresh()
    }
  },
  data() {
    return {
      deviceId: '',
      apps: [],
      largeIcon: true,
    }
  },
  methods: {
    refresh() {
      this.deviceId = this.$route.params.device
      axios.get('/api/apps/' + this.deviceId).then(({ data }) => this.apps = data)
    }
  },
  mounted() {
    // todo: vuex
    this.refresh()
  }
}
</script>
