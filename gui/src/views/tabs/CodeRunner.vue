<template>
  <div>
    <nav class="toolbar">
      <button class="button" :disabled="loading" @click="run"
        :class="{ 'is-loading': loading }">
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
            <li v-for="(log, i) in logs" :key="i">
              <!-- todo: refactor to v-bind:is -->
              <div v-if="log.subject === 'console.message'" :class="log.level">
                <b-icon icon="cancel" v-if="log.level === 'error'"></b-icon>
                <b-icon icon="warning" v-if="log.level === 'warn'"></b-icon>
                <b-icon icon="info" v-if="log.level === 'log'"></b-icon>

                <data-field v-for="(value, key) in log.args" :key=key
                  root="true" class="arg" :field="{ value }" :depth="0">
                </data-field>
              </div>

              <template v-if="log.subject === 'eval' ">
                <b-icon icon="chevron_right"></b-icon>
                <code>{{ log.source }}</code>
              </template>

              <template v-if="log.subject === 'result'">
                <b-icon icon="chevron_left"></b-icon>
                <data-field
                  root="true"
                  class="arg"
                  :field="{ value: log.result }">
                </data-field>
              </template>

              <div v-if="log.subject === 'error' " class="error">
                <b-icon icon="cancel"></b-icon>
                <pre>Uncaught {{ log.error.stack || log.error }}</pre>
              </div>

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

const KEY_FRIDA_SCRIPT = '/frida/script'

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
async function initMonaco(container, value) {
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
    value: value || await import('~/assets/editor.default.txt'),
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
      loading: true,
      scriptId: null,
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
    async cleanup() {
      this.clear()
      if (this.scriptId) {
        // clean up previous script
        try {
          console.log(await this.socket.call('unload', this.scriptId))
        } catch(_) {
          console.warn('failed to unload script', _)
        }
        this.scriptId = null
      }
    },
    async run(socket) {
      this.loading = true
      await this.cleanup()

      const source = this.editor.getValue()
      this.logs.push({
        subject: 'eval',
        source: source.length > 40 ? 
          source.substr(0, 40) + '...' :
          source,
      })

      try {
        const { status, uuid, error, type, value } = await this.socket.call('eval', source)
        this.scriptId = uuid

        if (status === 'ok') {
          console.log('[userscript] result:', type, value)
          this.logs.push({
            subject: 'result',
            result: value,
          })
        } else if (status === 'failed') {
          console.error(`[userscript] Uncaught frida`, error.stack || `${error}`)
          this.logs.push({
            subject: 'error',
            error,
          })
        }
      } catch(error) {
        this.logs.push({
          subject: 'error',
          error,
        })
      } finally {
        this.loading = false
      }
    },
    onMessage(data) {
      console.log('[debug onmessage]', data)

      const { hasData, payload, subject, type } = data
      if (subject === 'message') {
        this.logs.push(payload)
      } else {
        console.info('unknown message', data)
      }
    },
  },
  mounted() {
    initMonaco(this.$refs.editor, localStorage.getItem(KEY_FRIDA_SCRIPT)).then(editor => {
      this.monacoReady = true
      this.loading = false
      this.editor = editor
    })
    this.socket.on('userScript', this.onMessage)
  },
  beforeDestroy() {
    this.socket.off('userScript', this.onMessage)
    if (this.editor) {
      localStorage.setItem(KEY_FRIDA_SCRIPT, this.editor.getValue())
      this.editor.getModel().dispose()
      this.editor.dispose()
    }
    this.cleanup()
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

.messages > li {
  border-bottom: 1px solid #ddd;

  > div {
    &.warn {
      color: rgb(91, 59, 8);
      background: rgb(255, 251, 231);
    }

    &.error {
      color:rgb(252, 17, 31);
      background: #fff0f0;
    
      pre {
        background: none;
        color: inherit;
        padding: 0;
        display: inline-block;
      }
    }
  }

  &:last-of-type {
    border-bottom: none;
  }
}

</style>
