<template>
  <div class="hexview">
    <h2 class="title">TextViewer</h2>
    <b-field><b-switch v-model="hex">Hex View</b-switch></b-field>
    <pre class="hexdump">{{ content }}</pre>
    <p class="is-size-7">File large than 1kb will be truncated</p>
  </div>
</template>

<script>
export default {
  props: {
    raw: ArrayBuffer,
  },
  data() {
    return {
      hex: true,
    }
  },
  computed: {
    content() {
      return this.hex ? this.hexdump : new TextDecoder('utf8').decode(this.raw)
    },
    hexdump() {
      let view = new DataView(this.raw)
      let dump = '      0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F 0123456789ABCDEF'

      for (let i = 0; i < this.raw.byteLength; i += 16) {
        dump += `\n${('0000' + i.toString(16).toUpperCase()).slice(-4)} `
        for (let j = 0; j < 16; j++) {
          let ch = i + j > this.raw.byteLength - 1 ?
            '  ' :
            (0 + view.getUint8(i + j).toString(16).toUpperCase()).slice(-2)

          dump += `${ch} `
        }

        dump += String.fromCharCode.apply(null,
          new Uint8Array(this.raw.slice(i, i + 16)))
          .replace(/[^\x20-\x7E]/g, '.')
      }

      return dump
    },
  }
}
</script>