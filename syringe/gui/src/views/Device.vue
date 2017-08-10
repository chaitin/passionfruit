<template>
  <div>
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

    <div class="content"><h2 class="title">Select an App to inspect</h2></div>

    <div class="is-clearfix">
      <ul v-if="isGrid" class="app-list">
        <li v-for="app in apps" :key="app.identifier" :class="{'is-success': app.pid }">
          <icon :icon="app.largeIcon" class="icon"></icon>
          <div class="content">
            <h3>{{ app.name }} </h3>
            <p class="has-text-grey">{{ app.identifier }}</p>
            <!-- <div class="tags has-addons" v-if="app.pid">
              <span class="tag is-success">pid</span>
              <span class="tag">{{ app.pid }}</span>
            </div> -->
          </div>
        </li>
      </ul>

      <b-table v-else
        :data="apps"
        :narrowed="isSmallIcon"
        :loading="false"
        :hasDetails="false"
        default-sort="name">

        <template scope="props">
          <b-table-column field="smallIcon" width="16" label="" v-show="isSmallIcon">
            <icon :icon="props.row.smallIcon"></icon>
          </b-table-column>

          <b-table-column field="largeIcon" width="32" label="" v-show="isLargeIcon">
            <icon :icon="props.row.largeIcon"></icon>
          </b-table-column>

          <b-table-column field="name" label="Name" sortable>
            {{ props.row.name }}
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
</template>

<script>
import axios from 'axios'
import Icon from '~/components/Icon.vue'

export default {
  components: {
    Icon
  },
  watch: {
    $route(from, to) {
      this.refresh()
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
    }
  },
  data() {
    return {
      deviceId: '',
      apps: [],
      largeIcon: true,
      view: 'grid',
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

<style lang="scss">
.app-list {
  display: flex;
  flex-wrap: wrap;
  margin: 4em 0;

  li {
  	display: flex;
    padding: 4px;
    margin-bottom: 1em;
    overflow: hidden;

    @for $i from 1 through 6 {
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
      margin-left: 1em;
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
