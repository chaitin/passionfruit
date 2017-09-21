const checksec = require('./checksec')
const info = require('./info')
const lsof = require('./lsof')
const imports = require('./imports')
const { classes, methods } = require('./classdump')

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
}