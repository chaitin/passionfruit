<template>
  <div class="data-field">
    <div v-if="root && !isExpandableType">
      <span
        class="value"
        :class="valueClass"
        v-html="formattedValue" />
    </div>
    <div
      v-else
      class="self"
      :style="{ marginLeft: depth * 14 + 'px' }"
      @click="onClick"
    >
      <span
        v-show="isExpandableType"
        class="arrow right"
        :class="{ rotated: expanded }"
      ></span>
  
      <span class="key" :class="{ abstract: fieldOptions.abstract }">{{ field.key }}</span>
      <span class="colon" v-if="!fieldOptions.abstract">:</span>
      <span
        class="value"
        :class="valueClass"
        v-html="formattedValue"
      />

    </div>

    <div class="children" v-if="expanded && isExpandableType">
      <data-field
        v-for="subField in limitedSubFields"
        :key="subField.key"
        :field="subField"
        :parent-field="field"
        :depth="depth + 1"
        :path="`${path}.${subField.key}`"
      />
      <span class="more"
        v-if="formattedSubFields.length > limit"
        @click="limit += 10"
        :style="{ marginLeft: depthMargin + 'px' }">
        ...
      </span>
    </div>
  </div>
</template>

<script>

/* 
  This file is forked from
  https://github.com/vuejs/vue-devtools/blob/842aa3572/src/devtools/components/DataField.vue

  Credits to vue-devtools contributors
*/

function isPlainObject(obj) {
  return Object.prototype.toString.call(obj) === '[object Object]'
}

function sortByKey(state) {
  return state && state.slice().sort((a, b) => {
    if (a.key < b.key) return -1
    if (a.key > b.key) return 1
    return 0
  })
}

const ESC = {
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  '&': '&amp;',
}

function escapeChar(a) {
  return ESC[a] || a
}

function escape(s) {
  return s.replace(/[<>"&]/g, escapeChar)
}

const rawTypeRE = /^\[object (\w+)]$/
const specialTypeRE = /^\[native (\w+) (.*)\]$/

function subFieldCount(value) {
  if (Array.isArray(value))
    return value.length
  else if (value && typeof value === 'object')
    return Object.keys(value).length
  return 0
}

export default {
  name: 'DataField',

  props: {
    field: Object,
    root: [String, Boolean],
    parentField: Object,
    depth: Number,
    path: [Number, String],
  },

  data() {
    return {
      limit: Array.isArray(this.field.value) ? 10 : Infinity,
      expanded: this.depth === 0 && this.field.key !== '$route' && (subFieldCount(this.field.value) < 5)
    }
  },

  computed: {
    depthMargin() {
      return (this.depth + 1) * 14 + 10
    },

    valueType() {
      const value = this.field.value
      const type = typeof value
      if (value == null) {
        return 'null'
      } else if (
        type === 'boolean' ||
        type === 'number'
      ) {
        return 'literal'
      } else if (value && value._custom) {
        return 'custom'
      } else if (type === 'string') {
        if (specialTypeRE.test(value)) {
          const [, specialType] = specialTypeRE.exec(value)
          return `native ${specialType}`
        }
        return 'string'
      } else if (Array.isArray(value)) {
        return 'array'
      } else if (isPlainObject(value)) {
        return 'plain-object'
      }
      return 'unknown'
    },

    rawValueType() {
      return typeof this.field.value
    },

    isExpandableType() {
      let value = this.field.value
      if (this.valueType === 'custom') {
        value = value._custom.value
      }
      const closed = this.fieldOptions.closed
      const closedDefined = typeof closed !== 'undefined'
      return (!closedDefined &&
        (
          Array.isArray(value) ||
          isPlainObject(value)
        )) ||
        (
          closedDefined &&
          !closed
        )
    },

    formattedValue() {
      const value = this.field.value
      if (this.fieldOptions.abstract) {
        return ''
      } else if (value === null) {
        return 'null'
      } else if (typeof value === 'undefined') {
        return 'undefined'
      } else if (this.valueType === 'custom') {
        return value._custom.display
      } else if (this.valueType === 'array') {
        return 'Array[' + value.length + ']'
      } else if (this.valueType === 'plain-object') {
        return 'Object' + (Object.keys(value).length ? '' : ' (empty)')
      } else if (this.valueType.includes('native')) {
        return escape(specialTypeRE.exec(value)[2])
      } else if (typeof value === 'string') {
        const typeMatch = value.match(rawTypeRE)
        return typeMatch ?
          escape(typeMatch[1]) :
          `<span>"</span>${escape(value)}<span>"</span>`
      } else if (isNaN(value)) {
        return 'NaN'
      } else if (value === Number.INFINITY) {
        return 'Infinity'
      } else if (value === Number.NEGATIVE_INFINITY) {
        return '-Infinity'
      }
      return value
    },

    formattedSubFields() {
      let value = this.field.value

      // CustomValue API
      const isCustom = this.valueType === 'custom'
      let inherit = {}
      if (isCustom) {
        inherit = value._custom.fields || {}
        value = value._custom.value
      }

      if (Array.isArray(value)) {
        value = value.map((item, i) => ({
          key: i,
          value: item,
          ...inherit
        }))
      } else if (typeof value === 'object') {
        value = Object.keys(value).map(key => ({
          key,
          value: value[key],
          ...inherit
        }))
        if (this.valueType !== 'custom') {
          value = sortByKey(value)
        }
      }
      return value
    },

    limitedSubFields() {
      return this.formattedSubFields.slice(0, this.limit)
    },

    fieldOptions() {
      return this.valueType === 'custom' ?
        Object.assign({}, this.field, this.field.value._custom) :
        this.field
    },

    valueClass() {
      const cssClass = [this.valueType, `raw-${this.rawValueType}`]
      if (this.valueType === 'custom') {
        const value = this.field.value
        value._custom.type && cssClass.push(`type-${value._custom.type}`)
        value._custom.class && cssClass.push(value._custom.class)
      }
      return cssClass
    }
  },

  methods: {
    onClick(event) {
      // Cancel if target is interactive
      if (event.target.tagName === 'INPUT' || event.target.className.includes('button')) {
        return
      }

      // Default action
      this.toggle()
    },

    toggle () {
      if (this.isExpandableType) {
        this.expanded = !this.expanded
      }
    },

    hyphen: v => v.replace(/\s/g, '-')
  }
}
</script>

<style lang="scss" scoped>
// Colors
$blue: #44A1FF;
$grey: #DDDDDD;
$darkerGrey: #CCC;
$blueishGrey: #486887;
$green: #42B983;
$darkerGreen: #3BA776;
$slate: #242424;
$white: #FFFFFF;
$orange: #DB6B00;
$red: #c41a16;
$black: #222;
$vividBlue: #0033cc;
$purple: #997fff;

// The min-width to give icons text...
$wide: 1050px;

// The min-height to give the tools a little more breathing room...
$tall: 350px;

// Theme
$active-color: $darkerGreen;
$border-color: $grey;
$background-color: $white;
$component-color: $active-color;
$hover-color: #E5F2FF;

$dark-active-color: $active-color;
$dark-border-color: lighten($slate, 10%);
$dark-background-color: $slate;
$dark-component-color: $active-color;
$dark-hover-color: #444;

// Arrow
$arrow-color: #333;

.arrow {
  display: inline-block;
  width: 0;
  height: 0;

  &.up {
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-bottom: 6px solid $arrow-color;
  }

  &.down {
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 6px solid $arrow-color;
  }

  &.right {
    border-top: 4px solid transparent;
    border-bottom: 4px solid transparent;
    border-left: 6px solid $arrow-color;
  }

  &.left {
    border-top: 4px solid transparent;
    border-bottom: 4px solid transparent;
    border-right: 6px solid $arrow-color;
  }

  transition: transform .1s ease;
  margin-right: 8px;
  opacity: .7;
  &.rotated {
    transform: rotate(90deg);
  }
}

.data-field {
  user-select: text;
  font-size: 12px;
  font-family: Menlo, Consolas, monospace;
  cursor: pointer;
}

.self {
  height: 20px;
  line-height: 20px;
  position: relative;
  white-space: nowrap;
  padding-left: 14px;

  span, div {
    display: inline-block;
    vertical-align: middle;
  }
  .arrow {
    position: absolute;
    top: 7px;
    left: 0px;
    transition: transform .1s ease;
    &.rotated {
      transform: rotate(90deg);
    }
  }
 
  .colon {
    margin-right: .5em;
    position: relative;
  }

  .type {
    color: $background-color;
    padding: 3px 6px;
    font-size: 10px;
    line-height: 10px;
    height: 16px;
    border-radius: 3px;
    margin: 2px 6px;
    position: relative;
    background-color: #eee;
    .dark & {
      color: #242424;
    }
  }
}

.key {
  color: #881391;
  .dark & {
    color: #e36eec;
  }
  &.abstract {
    color: $blueishGrey;
    .dark & {
      color: lighten($blueishGrey, 20%);
    }
  }
}

.value {
  display: inline-block;
  color: #444;
  &.string, &.native {
    color: $red;
  }
  &.string {
    span {
      color: $black;
      .dark & {
        color: $red;
      }
    }
  }
  &.null {
    color: #999;
  }
  &.literal {
    color: $vividBlue;
  }
  &.raw-boolean {
    width: 36px;
  }
  &.custom {
    &.type-component {
      color: $green;
      &::before,
      &::after {
        color: $darkerGrey;
      }
      &::before {
        content: '<';
      }
      &::after {
        content: '>';
      }
    }
    &.type-function {
      font-style: italic;
      span {
        color: $vividBlue;
        font-family: 'dejavu sans mono', monospace;
        .platform-mac & {
          font-family: Menlo, monospace;
        }
        .platform-windows & {
          font-family: Consolas, 'Lucida Console', 'Courier New', monospace;
        }
        .dark & {
          color: $purple;
        }
      }
    }
    &.type-component-definition {
      color: $green;
      span {
        color: $darkerGrey;
      }
    }
  }

  .dark & {
    color: #bdc6cf;
    &.string, &.native {
      color: #e33e3a;
    }
    &.null {
      color: #999;
    }
    &.literal {
      color: $purple;
    }
  }
}

.more {
  cursor: pointer;
  display: inline-block;
  border-radius: 4px;
  padding: 0 4px 4px;
  &:hover {
    background-color: #eee;
  }
}

</style>