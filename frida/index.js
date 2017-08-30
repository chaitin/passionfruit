const checksec = require('./checksec')
const info = require('./info')
const lsof = require('./lsof')
const { classes, methods } = require('./classdump')


rpc.exports = {
  checksec,
  info,

  lsof,
  classes,
  methods,
}