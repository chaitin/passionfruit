<template>
  <div class="container is-fluid">
    <nav class="tabs is-centered sub-nav" ref="nav">
      <ul data-route="storage">
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

      <ul data-route="console">
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
  mounted() {
    this.updateSubNav()
  },
  methods: {
    updateSubNav() {
      for (let element of this.$refs.nav.children)
        element.style.display = 
          this.$route.matched.some(route => route.name === element.dataset.route) ?
            'flex' : 'none'
    }
  },
  watch: {
    $route(val) {
      this.updateSubNav()
    }
  }
}
</script>

<style scoped>
.sub-nav > ul {
  display: none;
}
</style>