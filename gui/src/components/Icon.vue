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
      ctx.putImageData(imageData, (canvas.width - width) / 2, (canvas.height - height) / 2)
      ctx.scale(canvas.width / width, canvas.height / height)
    }
  },
  watch: {
    icon(val) {
      this.paint()
    }
  },
  computed: {
    w() {
      return (this.width > 0 ? this.width : (this.icon && this.icon.width)) || 32
    },
    h() {
      return (this.height > 0 ? this.height : (this.icon && this.icon.height)) || 32
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
