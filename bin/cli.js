#!/usr/bin/env node
const net = require('net')

const app = require('../app')
const config = require('../lib/config')

function usage() {
  console.log('usage: passionfruit {server|syslog}')
  process.exit(-1)
}

function syslog() {
  const port = parseInt(process.argv[3], 10)
  if (Number.isNaN(port))
    console.log('usage: passionfruit console [port]')

  net.connect({ host: 'localhost', port })
    .on('end', () => process.exit(0))
    .pipe(process.stdout)
}

function main() {
  if (process.argv.length > 2) {
    const action = process.argv[2].toLowerCase()
    if (action === 'syslog')
      return syslog()
    if (action !== 'server')
      return usage()
  }
  return app.start(config)
}

main()
