<template>
  <figure class="button is-loading is-primary is-outlined no-border" :style="css"></figure>
</template>

<script>
export default {
  props: ['height', 'width', 'radius'],
  computed: {
    fontSize() {
      let { radius } = this
      if (!radius)
        return '1em'

      if (typeof radius === 'number') {
        return radius / 16 + 'em'
      }

      const matched = /^(\d+(?:\.\d+)?)(%|px|em|rem|vh|wh)$/.exec(radius)
      if (!matched)
        throw new Error(`invalid radius expression: ${radius}`)

      let [_, number, unit] = matched
      let val = +number
      if (isNaN(val))
        throw new Error(`invalid radius size: ${number}`)

      if (unit == 'px')
        return val / 16 + 'em'
      else if (unit == '%')
        return val / 100 + 'em'
      else
        return radius
    },
    css() {
      return {
        width: this.width,
        height: this.height,
        fontSize: this.fontSize,
      }
    }
  }
}
</script>

<style lang="scss">
.no-border {
  border: none;
}
</style>