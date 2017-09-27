import checksec from './checksec'
import lsof from './lsof'
import imports from './imports'
import cookies from './binarycookie'
import urlOpen from './ipc'
import keychain from './keychain'


import { info } from './info'
import { classes, methods } from './classdump'
import { tables, data, query } from './sqlite'
import { ls, home, plist, text, download } from './finder'
import { dumpWindow } from './ui'


rpc.exports = {
  checksec,
  info,

  lsof,
  classes,
  methods,
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

  dumpKeyChain: keychain.list,
}