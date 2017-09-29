<template>
  <div>
    <ul class="console">
      <li v-for="(item, i) in list" :key="i">
        <p>
          <span>
            <span v-if="item.event === 'call'">
              <b-icon icon="subdirectory_arrow_right"></b-icon>
              <span>Call</span>
            </span>
            <span v-if="item.event === 'return'">
              <b-icon icon="subdirectory_arrow_left"></b-icon>
              <span>Return</span>
            </span>
          </span>
          <b-tag>{{ item.time | datetime }}</b-tag>
          <code>{{ item.lib }}!{{ item.func }}</code>
        </p>

        <ul class="args">
          <li v-for="(arg, j) in item.args" :key="j">{{ arg }}</li>
        </ul>

        <ul class="backtrace">
          <li v-for="(bt, j) in item.backtrace" :key="j">
            <span>{{ bt.address }}</span>
            <span>{{ bt.name }}</span>
            <span>{{ bt.moduleName }}</span>
          </li>
        </ul>
      </li>
    </ul>
  </div>
</template>

<script>
import { mapGetters, mapMutations } from 'vuex'
import { CONSOLE_ACTIVE, CONSOLE_LIST, CONSOLE_UNREAD } from '~/vuex/types'

export default {
  computed: {
    ...mapGetters({
      list: CONSOLE_LIST,
      unread: CONSOLE_UNREAD,
    })
  },
  data() {
    return {
      loading: false,
    }
  },
  filters: {
    datetime: ts => new Date(ts).toLocaleString('en-US', {
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
      hour12: false
    })
  },
  methods: {
    ...mapMutations({
      setActive: CONSOLE_ACTIVE,
    })
  },
  beforeRouteEnter(to, from, next) {
    next(vm => vm.setActive(true))
  },
  beforeRouteLeave(to, from, next) {
    this.setActive(false)
    next()
  }
}
</script>

<style>
ul.backtrace {
  font-family: monospace;
  font-size: 14px;
}

ul.args {
  font-family: monospace;
}
</style>
