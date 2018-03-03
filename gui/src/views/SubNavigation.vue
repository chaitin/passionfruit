<template>
  <div class="container is-fluid">
    <nav class="tabs is-centered">
      <ul v-if="isStorage">
        <li>
          <router-link :to="{ name: 'keychain' }">
            <span>KeyChain</span>
          </router-link>
        </li>
        <li>
          <router-link :to="{ name: 'cookies' }">
            <span>Cookies</span>
          </router-link>
        </li>
        <li>
          <router-link :to="{ name: 'userdefaults' }">
            <span>UserDefaults</span>
          </router-link>
        </li>
      </ul>

      <ul v-if="isConsole">
        <li>
          <router-link :to="{ name: 'output' }">
            <span>Output</span>
          </router-link>
        </li>
        <li>
          <router-link :to="{ name: 'runner'} ">
            <span>Code Runner</span>
          </router-link>
        </li>
      </ul>
    </nav>
    <div class="tab-content">
      <router-view class="tab-item"></router-view>
    </div>
  </div>
</template>

<script>
export default {
  computed: {
    isStorage() {
      return this.isChildOf('storage')
    },
    isConsole() {
      return this.isChildOf('console')
    }
  },
  methods: {
    isChildOf(name) {
      return this.$route.matched.some(route => route.name === name)
    },
  }
}
</script>
