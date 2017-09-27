<template>
  <b-field>
    <p class="control">
      <span class="button is-static">{{ scheme }}://</span>
    </p>
    <b-input placeholder="" v-model="url" expanded></b-input>
    <p class="control">
      <button class="button is-primary" @click="open"><b-icon icon="open_in_new"></b-icon></button>
    </p>
  </b-field>
</template>

<script>
export default {
  props: {
    scheme: String,
  },
  data() {
    return {
      expand: false,
      url: '',
    }
  },
  methods: {
    toggle() {
      this.expand = !this.expand
    },
    open() {
      this.$emit('open', this.scheme + '://' + this.url)
    }
  }
}
</script>

<style>

</style>
