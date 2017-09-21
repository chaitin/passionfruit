<template>
  <ul>
    <li v-for="item in children" :key="item.name" v-if="item.type == 'directory'" >
      <folder-tree :children="item.children" :name="item.name"></folder-tree>
      <b-icon icon="folder"></b-icon> <span>{{ item.name }}</span>
    </li>
  </ul>
</template>

<script>
export default {
  name: 'FolderTree',
  props: {
    'children': Array,
    'name': String,
  },
}
</script>