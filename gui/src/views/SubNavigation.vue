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
  },
  methods: {
    isChildOf(name) {
      return this.$route.matched.some(route => route.name === name)
    },
  }
}
</script>
