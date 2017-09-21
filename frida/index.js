import checksec from './checksec'
import plist from './plist'
import lsof from './lsof'
import imports from './imports'

import { info } from './info'
import { classes, methods } from './classdump'
import { ls, home } from './finder'


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
}