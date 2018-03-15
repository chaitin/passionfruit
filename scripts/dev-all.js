#!/usr/bin/env node

require('colors')

const { spawn } = require('child_process')
const compile = require('./lib/compile')
const nodemon = require('nodemon')

process.env.NODE_ENV = 'development'

// start frida compiler
compile.run(true)

// server side

const TAG_SERVER = '[Server]'.magenta

nodemon({
  script: 'app.js',
  ext: 'js json',
  watch: ['lib', 'app.js'],
})

nodemon
  .on('start', () => console.log(TAG_SERVER, 'Server started.'))
  .on('restart', files => console.log(TAG_SERVER, 'App restarted due to: ', files))
  .on('quit', () => {
    console.log(TAG_SERVER, 'Server has been terminated.'.red)
    process.exit()
  })

// frontend
const TAG_WEBPACK = '[WebPack]'.cyan
const webpack = spawn('npm', ['run', 'dev'], {
  cwd: 'gui',
  shell: true,
  stdio: 'inherit',
})

webpack.on('exit', () => {
  console.warn(TAG_WEBPACK, 'WebPack has been terminated.'.red)
  process.exit()
})

process.on('SIGINT', () => {
  if (!webpack.killed)
    webpack.kill()
})
