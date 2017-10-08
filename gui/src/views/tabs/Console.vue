<template>
  <div>
    <b-field>
      <b-switch v-model="logging">Live</b-switch>
    </b-field>
    <ul class="console">
      <li v-for="(item, i) in list" :key="i">
        <span class="time">
          <b-tag>{{ item.time | datetime }}</b-tag>
        </span>
        <span class="event">
          <b-tag type="is-dark">{{ item.event }}</b-tag>
        </span>
        <span class="expression">
          <code>{{ item | expr }}</code>
        </span>

        <b-dropdown position="is-bottom-left" v-if="item.backtrace">
          <a slot="trigger">
            <b-tooltip label="Traceback" position="is-left">
              <b-icon icon="view_headline"></b-icon>
            </b-tooltip>
          </a>
          <b-dropdown-item custom>
            <div class="content">
              <ul class="backtrace">
                <li v-for="(bt, j) in item.backtrace" :key="j">
                  <b-tag class="addr">{{ bt.address }}</b-tag>
                  <span class="symbol">{{ bt.moduleName }}!{{ bt.name }}</span>
                </li>
              </ul>
            </div>
          </b-dropdown-item>
        </b-dropdown>
      </li>
    </ul>
  </div>
</template>

<script>
import { mapGetters, mapMutations } from 'vuex'
import { CONSOLE_ACTIVE, CONSOLE_LIST, CONSOLE_UNREAD, CONSOLE_RUNNING } from '~/vuex/types'

export default {
  computed: {
    logging: {
      get() {
        return this.$store.state.output.logging
      },
      set(val) {
        this.$store.commit(CONSOLE_RUNNING, val)
      }
    },
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
    expr(item) {
      let router = {
        'objc-call': () => `${item.clazz}!${item.sel}(${item.args.join(', ')})`,
        'objc-return': () => `=${item.ret}`,
        'call': () => `${item.lib}!${item.func}(${item.args.join(', ')})`,
        'return': () => `=${item.ret}`,
      }
      if (router.hasOwnProperty(item.event))
        return router[item.event].call(null)
      else
        return item.arguments
      // return '!ERR: Unknown type: ' + item.event
    },
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

<style lang="scss">
ul.console {
  margin: 0;
  display: flex;
  flex-direction: column;

  li {
    display: flex;
    flex-direction: row;

    .time {
      width: 140px;
      margin: 2px 2px 2px;
    }

    .event {
      width: 120px;
      margin: 2px 2px 2px 10px;
    }

    .expression {
      flex: 1;
      margin: 2px 10px 2px 2px;
      word-break: break-all;
      word-wrap: none;
      text-overflow: ellipsis;
    }
  }

  ul.backtrace {
    margin: 0;
    font-family: monospace;
    font-size: 14px;
    max-width: 80vw;

    .addr {
      margin-right: 4px;
    }
  }
}
</style>
