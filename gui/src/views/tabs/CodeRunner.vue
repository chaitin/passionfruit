<template>
  <div>
    <div ref="editor" class="editor"></div>
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
  }

  window.require(['vs/editor/editor.main'], async () => {
    const editor = monaco.editor.create(container, {
      value: `// paste frida script here`,
      language: 'javascript',
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
        lib : ['es5'],
        allowNonTsExtensions: true
    })

    // auto complete
    monaco.languages.typescript.javascriptDefaults.addExtraLib(
      await import('frida-gum-types/frida-gum/frida-gum.d.ts'), 'frida-gum.d.ts')
    
    monaco.languages.typescript.javascriptDefaults.addExtraLib(
      await import('~/assets/lib.es5.d.ts'), 'lib.es5.d.ts')
  })
}

export default {
  data() {
    return {
      monacoReady: false,
    }
  },
  mounted() {
    initMonaco(this.$refs.editor).then(this.monacoReady = true)
  },
  beforeDestroy() {

  }
}
</script>

<style scoped>
.editor {
  min-height: 360px;
}
.placeholder {
  display: none;
}
</style>
