<template>
  <canvas ref="icon" :width="icon.width" :height="icon.height"></canvas>
</template>

<script>

export default {
  name: 'icon',
  props: {
    icon: Object,
  },
  methods: {
    paint() {
      let canvas = this.$refs.icon
      if (!canvas)
        return
      let ctx = canvas.getContext('2d')
      let { width, height, pixels } = this.icon
      let imageData = ctx.createImageData(width, height)
      let buf = Uint8ClampedArray.from(atob(pixels), c => c.charCodeAt())
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
