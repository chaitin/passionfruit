const checksec = require('./checksec')
const info = require('./info')
const { classes, methods } = require('./classdump')


rpc.exports = {
  checksec,
  info,

  classes,
  methods,
}