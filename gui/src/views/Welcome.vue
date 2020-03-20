<template>
  <div class="container is-fluid">
    <div class="columns section">
      <div class="column is-one-quarter">
        <h1 class="title has-text-grey-darker">
          <img class="logo" src="../assets/logo.svg" alt="Passionfruit" />
        </h1>
        <aside class="menu">
          <p class="menu-label">Frida version: {{ version }}</p>
          <p class="menu-label">
            Devices
            <loading v-if="loadingDevices" class="is-pulled-right"></loading>
          </p>
          <ul class="menu-list">
            <li v-for="dev in devices" :key="dev.id">
              <router-link v-if="['local', 'tcp'].indexOf(dev.id) === -1" :to="{ name: 'apps', params: { device: dev.id } }">
                <icon :icon="dev.icon" :width="24" :height="24"></icon>
                {{ dev.name }}
                <button v-if="dev.type === 'remote' " class="is-pulled-right remove button is-text"
                  @click.stop.prevent="remove(dev.id)"><b-icon icon="remove_circle" type="is-danger"></b-icon></button>
              </router-link>
            </li>
            <li v-if="!devices.length">
              <b-icon icon="button error"></b-icon>No device found
            </li>
            <li>
              <a class="button add" @click="connect" type="is-light" icon-left="add_box">
                <b-icon icon="add_box"></b-icon>
                Connect Remote
              </a>
            </li>
          </ul>
          <p class="menu-label">General</p>
          <ul class="menu-list">
            <!-- <li><a><b-icon icon="settings"></b-icon> <span>Preference</span></a></li> -->
            <li>
              <a target="_blank" href="http://github.com/chaitin/passionfruit">
                <b-icon icon="open_in_browser"></b-icon>
                <span>Github</span>
              </a>
            </li>
          </ul>
        </aside>
      </div>

      <div class="column">
        <router-view></router-view>
      </div>
    </div>
  </div>
</template>

<script>
// TODO: refactor
import axios from 'axios'

import { mapGetters, mapActions } from "vuex";
import {
  GET_VERSION,
  GET_DEVICES,
  LOAD_DEVICES,
  DEVICES_LOADING
} from "~/vuex/types";
import Icon from "~/components/Icon.vue";
import Loading from "~/components/Loading.vue";

export default {
  components: {
    Icon,
    Loading
  },
  computed: {
    ...mapGetters({
      version: GET_VERSION,
      devices: GET_DEVICES,
      loadingDevices: DEVICES_LOADING
    })
  },
  methods: {
    connect() {
      this.$dialog.prompt({
        message: `Connect Remote Device via TCP`,
        inputAttrs: {
          placeholder: "192.168.1.100",
        },
        trapFocus: true,
        onConfirm(value) {
          axios.put('/device/add', value)
        }
      });
    },
    remove(id) {
      // todo: utils
      function escape(html) {
        const text = document.createTextNode(html)
        const container = document.createElement('p')
        container.appendChild(text)
        return container.innerHTML
      }

      const { $toast } = this
      this.$dialog.confirm({
        message: `Are you sure to remove ${escape(id)}`,
        type: 'is-danger',
        hasIcon: true,
        onConfirm(value) {
          // TODO: path traversal?
          axios.delete('/device/' + id.replace(/^tcp@/, ''), value)
            .catch(err => $toast.open({
              message: `failed to remove device`,
              type: 'is-danger'
            }))
        }
      });
    },
    ...mapActions({
      refresh: LOAD_DEVICES
    })
  },
  mounted() {
    this.refresh();
  }
};
</script>

<style scoped>
.add {
  margin-top: 0.5em;
  padding: 0.25em 0.75em;
  display: block;
  cursor: pointer;
}

.remove {
  cursor: pointer;
  background: transparent;
  border: none;
  margin-top: -4px;
  /* margin: 0.5em; */
}
</style>
