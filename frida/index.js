import checksec from './checksec'
import lsof from './lsof'
import imports from './imports'
import cookies from './binarycookie'
import urlOpen from './ipc'

import { info } from './info'
import { classes, methods } from './classdump'
import { ls, home, plist, text } from './finder'
import { tables, data, query } from './sqlite'

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

  cookies,
  urlOpen,

  tables,
  data,
  query,
}