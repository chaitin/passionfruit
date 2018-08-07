import { pipe, dup2, close, fcntl } from './lib/libc'


// sys/fcntl.h
const F_SETFL = 4
const O_NONBLOCK = 0x0004

const stderr = 2;
const SIZEOF_INT = 4; // for mac & iOS

const subject = 'syslog'
const fildes = Memory.alloc(SIZEOF_INT * 2)

let stream = null

export function start() {
  pipe(fildes)

  const input = Memory.readInt(fildes)
  const output = Memory.readInt(fildes.add(SIZEOF_INT))

  dup2(output, stderr)
  close(output)
  fcntl(input, F_SETFL, O_NONBLOCK)

  stream = new UnixInputStream(input)

  function read() {
    stream.read(4096).then((buf) => {
      if (buf.byteLength)
        send({ subject }, buf)

      setImmediate(read)
    })
  }

  setImmediate(read)
}

export function stop() {
  if (stream)
    stream.close()
}
