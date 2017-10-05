import checksec from './checksec'
import lsof from './lsof'
import imports from './imports'
import cookies from './binarycookie'
import urlOpen from './ipc'
import keychain from './keychain'

import { info } from './info'
import { classes, methods, inspect, proto } from './classdump'
import { tables, data, query } from './sqlite'
import { ls, home, plist, text, download } from './finder'
import { dumpWindow, toggleTouchID } from './ui'
import { hook, unhook, swizzle, unswizzle } from './hook'


toggleTouchID(false)
// hook('libSystem.B.dylib', 'open', { args: ['char *', 'int']})

hook('libsqlite3.dylib', 'sqlite3_open', { args: ['char *', 'int'], ret: 'int' })
hook('libsqlite3.dylib', 'sqlite3_prepare_v2', { args: ['pointer', 'char *', 'int', 'pointer', 'pointer'] })
hook('libsqlite3.dylib', 'sqlite3_bind_int', { args: ['pointer', 'int', 'int'] })
hook('libsqlite3.dylib', 'sqlite3_bind_null', { args: ['pointer', 'int'] })
hook('libsqlite3.dylib', 'sqlite3_bind_text', { args: ['pointer', 'int', 'char *', 'int', 'pointer'] })

swizzle('NSURL', 'URLWithString_')
swizzle('NSString', 'stringWithContentsOfFile_usedEncoding_error_')


rpc.exports = {
  checksec,
  info,

  lsof,
  classes,
  methods,
  inspect,
  proto,
  imports,

  ls,
  home,
  plist,
  text,
  download,

  cookies,
  urlOpen,

  tables,
  data,
  query,

  dumpWindow,
  toggleTouchID,

  dumpKeyChain: keychain.list,

  hook,
  unhook,
  swizzle,
  unswizzle,
}