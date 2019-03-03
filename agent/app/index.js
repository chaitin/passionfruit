import '@babel/polyfill'
import './runtime-ready'

import checksec from './checksec'
import cookies from './binarycookie'
import dumpdecrypted from './dumpdecrypted'
import screenshot from './screenshot'
import bypassJailbreak from './jailbreak'


import { imports, exports, modules } from './symbols'
import { start as startPasteboardMonitor } from './pasteboard'
import { list as dumpKeyChain } from './keychain'
import { info, userDefaults } from './info'
import { classes, ownClasses, inspect } from './classdump'
import { tables, data, query } from './sqlite'
import { ls, plist, text, download } from './finder'
import { dumpWindow, toggleTouchID } from './ui'
import { hook, unhook, swizzle, unswizzle } from './hook'
import { start as startSyslog, stop as stopSyslog } from './syslog'


// todo: add options

setImmediate(() => {
  startSyslog()
  toggleTouchID(false)
  bypassJailbreak(true)
  startPasteboardMonitor()

  // todo: common function template
  hook('libSystem.B.dylib', 'open', { args: ['char *', 'int'] })
  hook('libsqlite3.dylib', 'sqlite3_open', { args: ['char *', 'int'], ret: 'int' })
  hook('libsqlite3.dylib', 'sqlite3_prepare_v2', { args: ['pointer', 'char *', 'int', 'pointer', 'pointer'] })
  hook('libsqlite3.dylib', 'sqlite3_bind_int', { args: ['pointer', 'int', 'int'] })
  hook('libsqlite3.dylib', 'sqlite3_bind_null', { args: ['pointer', 'int'] })
  hook('libsqlite3.dylib', 'sqlite3_bind_text', { args: ['pointer', 'int', 'char *', 'int', 'pointer'] })

  swizzle('NSURL', 'URLWithString_', false)
  swizzle('NSString', 'stringWithContentsOfFile_usedEncoding_error_')
})

function unload() {
  // todo: destructor
  stopSyslog()
}

// todo: decorator?
rpc.exports = {
  checksec,
  info,
  userDefaults,

  modules,
  exports,
  classes,
  ownClasses,

  inspect,
  imports,

  ls,
  plist,
  text,
  download,

  cookies,

  tables,
  data,
  query,

  dumpWindow,
  toggleTouchID,

  dumpKeyChain,

  hook,
  unhook,
  swizzle,
  unswizzle,

  dumpdecrypted,
  screenshot,

  unload
}
