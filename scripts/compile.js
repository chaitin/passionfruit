#!/usr/bin/env node

const compile = require('./lib/compile')

const watch = process.argv.indexOf('watch') > -1
compile.run(watch)
