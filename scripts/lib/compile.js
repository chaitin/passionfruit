const compiler = require('frida-compile')

const TAG_FRIDA = '[Frida]'.yellow
const tasks = [{
  src: 'agent/app/index.js',
  dest: 'agent/app.bundle',
}]


exports.run = function(watch) {
  const opt = {
    bytecode: !watch,
    compress: false,
    babelify: true,
    sourcemap: watch,
    typeroots: true,
    useAbsolutePaths: false,
  }

  if (watch) {
    tasks.forEach(task => compiler.watch(task.src, `${task.dest}.js`, opt)
      .on('compile', (details) => {
        const count = details.files.length
        const { duration } = details
        console.log(TAG_FRIDA, `compiled ${count} file(s) in ${duration} ms`)
      }))
  } else {
    Promise
      .all(tasks.map(task => compiler.build(task.src, `${task.dest}.bin`, opt)))
      .catch(err => console.error(err))
  }
}
