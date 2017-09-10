<template>
  <div class="loading-container">
    <loading :radius="40"></loading>
  </div>
</template>

<script>
import Loading from '~/components/Loading.vue'
export default {
  components: { Loading },
}
</script>

<style>
.loading-container {
  display: flex;
  min-height: 80vh;
  align-items: center;
  justify-content: center;
}
</style>
