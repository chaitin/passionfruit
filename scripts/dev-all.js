require('colors')

const { spawn } = require('child_process')
const compiler = require('frida-compile')
const nodemon = require('nodemon')

// start frida compiler

const TAG_FRIDA = '[Frida]'.yellow
const tasks = require('./agents.json')
const opt = {
  bytecode: false,
  compress: false,
  babelify: true,
}

tasks.forEach(task => compiler.watch(task.src, task.dest, opt)
  .on('compile', (details) => {
    const count = details.files.length
    const { duration } = details
    console.log(TAG_FRIDA, `compiled ${count} file(s) in ${duration} ms`)
  }))

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
const webpack = spawn('npm' ,['run', 'dev'], {
  cwd: 'gui'
})

webpack.on('exit', () => {
  console.warn(TAG_WEBPACK, 'WebPack has been terminated.'.red)
  process.exit()
})

const redirect = data => console.log(TAG_WEBPACK, data.toString())

webpack.stdout.on('data', redirect)
webpack.stderr.on('data', redirect)

process.on('SIGINT', () => {
  if (!webpack.killed)
    webpack.kill()
})
