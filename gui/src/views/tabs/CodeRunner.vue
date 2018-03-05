<template>
  <div>
    <nav class="toolbar">
      <button class="button">
        <b-icon icon="play_arrow" size="is-large" type="is-success"></b-icon>
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
  data() {
    return {
      editor: null,
      monacoReady: false,
    }
  },
  mounted() {
    initMonaco(this.$refs.editor).then(editor => {
      this.monacoReady = true
      this.editor = editor
    })
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
