<template>
  <div class="container">
    <section>
      <h1>
        <nav class="breadcrumb" aria-label="breadcrumbs">
          <ul>
            <li><a href="/"><b-icon icon="home"></b-icon><span>Passionfruit</span></a></li>
            <li class="is-active"><a>{{ bundle }}</a></li>
          </ul>
        </nav>
      </h1>

      <b-field label="Path name and query string">
        <b-input type="textarea" v-model="url" @keyup.meta.enter="open"></b-input>
      </b-field>

      <b-field>
        <p class="control">
          <button class="button is-success" @click="open">Start</button>
        </p>
      </b-field>

      <h3>History</h3>
      <ul>
        <li v-for="(item, index) in history" :key="index">
          <a href="#" class="link" @click="start(item)">{{ item }}</a></li>
      </ul>

      <b-message title="Error" type="is-warning" v-show="err">
        {{ err }}            
      </b-message>
    </section>
  </div>
</template>

<script>
import axios from 'axios'

export default {
  mounted() {
    const { device, bundle, scheme } = this.$route.params
    this.device = device
    this.bundle = bundle
    this.url = scheme + '://'
  },
  data() {
    return {
      url: '',
      bundle: '',
      history: [],
      device: '',
      lastUrl: null,
      err: null,
    }
  },
  methods: {
    async open() {
      const { href } = new URL(this.url)
      if (href !== this.lastUrl)
        this.history.push(href)
      this.lastUrl = href
      const { device, bundle } = this
      axios.post('/url/start', { device, bundle, url: href })
        .then(({ data }) => {
          this.$toast.open(`successfully created process, pid ${data.pid}`)
        })
        .catch(err => {
          this.$toast.open({
            message: `failed to start url, reason: ${err}`,
            type: 'is-danger',
          })
        })
    },
  },
}
</script>

<style lang="scss" scoped>
h1 {
  margin-top: 40px;
}

.link {
  text-decoration: underline;
  color: #0af;
}
</style>

