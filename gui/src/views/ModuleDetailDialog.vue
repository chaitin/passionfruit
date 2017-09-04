<template>
  <!--todo: dialog
  <div class="column is-one-third" v-show="selected.item && selected.item.name">
    <article>
      <header><button class="delete is-pulled-right" aria-label="delete" @click="selected.item = {}"></button>
        Exported symbols from {{ selected.item.name }}</header>

      <ul v-if="selected.exports.length || selected.loading" class="exports">
        <li v-for="symbol in selected.exports" :key="symbol.name">
          <b-icon icon="functions" v-show="symbol.type == 'function'"></b-icon>
          <b-icon icon="title" v-show="symbol.type == 'symbol'"></b-icon>
          {{ symbol.name }}
        </li>
      </ul>
      <b-message v-else type="is-info" has-icon>
        No exported symbol found
      </b-message>
    </article>
  </div> -->
</template>