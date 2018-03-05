<template>
  <div>
    <nav class="toolbar">
      <button class="button" :disabled="!editor" @click="run">
        <b-icon icon="play_arrow" size="is-medium" type="is-success"></b-icon>
        <span>Run</span>
      </button>
    </nav>

    <div class="columns editor-body">
      <section class="column">
        <div class="editor" ref="editor"></div>
      </section>
      <section class="column">
        <div class="console"></div>
      </section>
    </div>

  </div>
</template>

<script>
import { mapGetters } from 'vuex'
import { GET_SOCKET } from '~/vuex/types'

import LoadingTab from '~/components/LoadingTab.vue'

// DAMN HACK
const loadScript = url => new Promise((resolve, reject) => {
  const tag = document.createElement('script')
  tag.setAttribute('src', url)
  tag.onload = () => {
    tag.parentNode.removeChild(tag)
    resolve()
  }
  // sorry, no IE
  tag.onerror = reject
  document.querySelector('head').appendChild(tag)
})

// wow let's go back to stone age
async function initMonaco(container) {
  if (!window.monaco) {
    await loadScript('/static/vs/loader.js')
    window.require.config({
      paths: {
        'vs': '/static/vs'
      }
    })

    await new Promise((resolve) =>
      window.require(['vs/editor/editor.main'], resolve))

    // auto complete
    monaco.languages.typescript.javascriptDefaults.addExtraLib(
      await import('frida-gum-types/frida-gum/frida-gum.d.ts'), 'frida-gum.d.ts')
    
    monaco.languages.typescript.javascriptDefaults.addExtraLib(
      await import('~/assets/duktape.d.ts'), 'duktape.d.ts')

  }

  const editor = monaco.editor.create(container, {
    value: `console.log(Process.enumerateModulesSync()); // list all modules\n`,
    language: 'javascript',
    automaticLayout: true,
  })

  // validation settings
  monaco.languages.typescript.javascriptDefaults.setDiagnosticsOptions({
    noSemanticValidation: true,
    noSyntaxValidation: false
  })

  // remove browser object models
  monaco.languages.typescript.javascriptDefaults.setCompilerOptions({
    target: monaco.languages.typescript.ScriptTarget.ES5,
    noLib : true,
    allowNonTsExtensions: true
  })

  return editor
}

export default {
  components: { LoadingTab },
  data() {
    return {
      loading: false,
      editor: null,
      monacoReady: false,
    }
  },
  computed: {
    ...mapGetters({
      socket: GET_SOCKET,
    })
  },
  methods: {
    run(socket) {
      this.loading = true
      this.socket.call('eval', this.editor.getValue())
        .then(result => {
          // if (typeof result === 'object')
          console.log('eval', result)
        })
        .finally(() => this.loading = false)
    },
  },
  mounted() {
    initMonaco(this.$refs.editor).then(editor => {
      this.monacoReady = true
      this.editor = editor
    })

    console.log(this.socket)
  },
  beforeDestroy() {
    if (this.editor) {
      this.editor.getModel().dispose()
      this.editor.dispose()

      // todo: save draft to localStorage
    }
  }
}
</script>

<style lang="scss" scoped>
.editor {
  min-height: 480px;
}

.editor-body {
  margin-top: 10px;
}

.placeholder {
  display: none;
}
</style>
