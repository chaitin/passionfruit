<template>
  <div class="container">
    <section>
      <h1>
        <nav class="breadcrumb" aria-label="breadcrumbs">
          <ul>
            <li><a href="/"><b-icon icon="home"></b-icon><span>Passionfruit</span></a></li>
            <li class="is-active"><a>URL Scheme Test</a></li>
          </ul>
        </nav>
      </h1>
      <b-field>
        <b-select class="prefix" placeholder="Select a scheme" icon="home" tabindex="1" v-model="scheme">
          <optgroup label="Public">
            <option :value="url" v-for="(url, index) in schemes['public']"
              :key="index">{{ url }}://</option>
          </optgroup>
          <optgroup label="Private">
            <option :value="url" v-for="(url, index) in schemes['private']"
              :key="index">{{ url }}://</option>
          </optgroup>
        </b-select>
        <b-input placeholder="" expanded tabindex="2" v-model="url"
          @keyup.enter="open"></b-input>
        <p class="control">
          <button class="button is-success" @click="open">Start</button>
        </p>
      </b-field>

      <ul>
        <li v-for="(item, index) in history" :key="index">
          <a href="#" @click="start(item)">{{ item }}</a></li>
      </ul>

      <b-message title="Error" type="is-warning" v-show="err">
        {{ err }}            
      </b-message>
    </section>
  </div>
</template>

<script>

export default {
  mounted() {
    let { device, bundle, scheme } = this.$route.params
    console.log('args', device, bundle, scheme)
  },
  data() {
    return {
      schemes: {
        'private': [],
        'public': [],
      },
      history: [],
      scheme: '',
      url: '',
      device: '',
      loading: false,
      err: null,
    }
  },
  methods: {
    async open() {
      const url = new URL([this.scheme, this.body].join(':')).href
      this.history.push(url)
      // todo: post
    },
  },
}
</script>

<style lang="scss" scoped>
h1 {
  margin-top: 40px;
}

.prefix {
  max-width: 240px;
}
</style>

