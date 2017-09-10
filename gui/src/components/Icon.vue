<template>
  <canvas ref="icon" :width="w" :height="h">
  </canvas>
</template>

<script>

export default {
  name: 'icon',
  props: {
    icon: Object,
    width: Number,
    height: Number
  },
  methods: {
    paint() {
      let canvas = this.$refs.icon
      if (!this.icon)
        return setTimeout(() => this.paint(), 20) // retry

      let ctx = canvas.getContext('2d')
      let { width, height, pixels } = this.icon
      let imageData = ctx.createImageData(width, height)
      try {
        pixels = atob(pixels)
      } catch (ex) {
        return
      }
      let buf = Uint8ClampedArray.from(pixels, c => c.charCodeAt())
      imageData.data.set(buf)
      ctx.clearRect(0, 0, canvas.width, canvas.height)
      ctx.putImageData(imageData, 0, 0)
    }
  },
  watch: {
    icon(val) {
      this.paint()
    }
  },
  computed: {
    w() {
      return (this.icon ? this.icon.width : this.width) || 32
    },
    h() {
      return (this.icon ? this.icon.height : this.height) || 32
    }
  },
  mounted() {
    this.paint()
  }
}

</script>

<style scoped>
canvas {
  display: inline-block;
  vertical-align: middle;
}
</style>
