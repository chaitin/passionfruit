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
      let ctx = canvas.getContext('2d')
      let { width, height, pixels } = this.icon
      let imageData = ctx.createImageData(width, height)
      let buf = Uint8ClampedArray.from(atob(pixels), c => c.charCodeAt())
      imageData.data.set(buf)
      ctx.putImageData(imageData, 0, 0)
    }
  },
  watch: {
    pixels() {
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
