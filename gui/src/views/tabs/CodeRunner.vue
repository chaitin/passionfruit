<template>
  <div>
    <nav class="toolbar">
      <button class="button" :disabled="!editor" @click="run">
        <b-icon icon="play_arrow" size="is-medium" type="is-success"></b-icon>
        <span>Run</span>
      </button>
      <button class="button" @click="clear">
        <b-icon icon="clear" size="is-medium" type="is-danger"></b-icon>
        <span>Clear Console</span>
      </button>
    </nav>

    <div class="columns editor-body">
      <section class="column">
        <div class="editor" ref="editor"></div>
      </section>
      <section class="column">
        <div class="console">
          <ul class="messages">
            <li v-for="(log, i) in logs" :key=i>
              <b-message :type="'is' + log.level">
                <div>
                  <data-field v-for="(value, key) in log.args" :key=key
                    class="arg"
                    :field="{ value, key: '' }"
                    :depth="0"
                    :path="key">
                  </data-field>
                </div>
              </b-message>
            </li>
          </ul>
        </div>
      </section>
    </div>

  </div>
</template>

<script>
import { mapGetters } from 'vuex'
import { GET_SOCKET } from '~/vuex/types'

import DataField from '~/components/DataField.vue'

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
  components: { DataField },
  data() {
    return {
      loading: false,
      editor: null,
      monacoReady: false,
      uuid: null,
      logs: [],
    }
  },
  computed: {
    ...mapGetters({
      socket: GET_SOCKET,
    })
  },
  methods: {
    clear() {
      this.logs = []
    },
    async run(socket) {
      this.loading = true
      
      if (this.scriptId) {
        // clean up previous script
        try {
          await this.socket.call('unload', scriptId)
        } catch(_) {}
      }

      try {
        const { result, uuid } = await this.socket.call('eval', this.editor.getValue())
        this.scriptId = uuid
        
        // todo: log result
      } catch(_) {
        // todo: log error
      } finally {
        this.loading = false
      }
    },
    onMessage(data) {
      console.log('[debug onmessage]', data)

      const { hasData, payload, subject, type } = data
      if (subject === 'message') {
        this.logs.push(payload)
      }
    },
  },
  mounted() {
    initMonaco(this.$refs.editor).then(editor => {
      this.monacoReady = true
      this.editor = editor
    })
    this.socket.on('userScript', this.onMessage)
  },
  beforeDestroy() {
    this.socket.off('userScript', this.onMessage)
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

.console .arg {
  display: inline-block;
  margin-right: 20px;
}

</style>
