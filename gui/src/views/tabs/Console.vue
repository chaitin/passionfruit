<template>
  <div>
    <p>{{ unread }}</p>
    <p>{{ list }}</p>
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

