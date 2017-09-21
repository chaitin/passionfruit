import checksec from './checksec'
import info from './info'
import lsof from './lsof'
import imports from './imports'
import { classes, methods } from './classdump'
import { ls, home } from './finder'
import plist from './plist'


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